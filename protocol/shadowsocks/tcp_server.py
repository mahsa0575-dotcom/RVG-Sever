# tcp_server.py
# ══════════════════════════════════════════════════════════════════════════════
# Shadowsocks — سرور TCP بومی (ss:// کلاسیک، بدون پلاگین)
# یک سرور asyncio به‌ازای هر کانفیگ با پورت اختصاصی خودش (توسط port_manager).
# هندشیک: salt + چانک‌های AEAD؛ اولین payload = آدرس مقصد (فرمت SOCKS5).
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import secrets
from datetime import datetime, timezone

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    schedule_save,
    log_activity,
)
from protocol.vless.vless import check_and_use, _QuotaGate
from protocol.shadowsocks.shadowsocks import (
    RELAY_BUF,
    WRITE_HIGH_WATER,
    _AEADStream,
    _tune_socket,
    parse_socks5_addr,
)

HANDSHAKE_TIMEOUT = 15.0
HANDSHAKE_MAX = 64 * 1024


async def _handle_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "نامشخص"
    conn_id = secrets.token_urlsafe(6)
    uuid = None

    try:
        # ── هندشیک: جمع‌آوری بایت‌ها تا تطبیق یکی از لینک‌های SS فعال ──
        loop = asyncio.get_event_loop()
        deadline = loop.time() + HANDSHAKE_TIMEOUT
        raw = bytearray()
        match = None
        while loop.time() < deadline:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(RELAY_BUF), timeout=max(0.1, deadline - loop.time())
                )
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            raw += chunk
            match = await _match(bytes(raw))
            if match:
                break
            if len(raw) > HANDSHAKE_MAX:
                break

        if not match:
            logger.warning(f"🚫 SS-TCP rejected [{conn_id}] ip={ip} (no matching key)")
            writer.close()
            return
        uuid, stream, chunks = match

        async with LINKS_LOCK:
            link = LINKS.get(uuid)
        if not is_link_allowed(link):
            writer.close()
            return

        connections[conn_id] = {
            "uuid": uuid,
            "ip": ip,
            "transport": "shadowsocks-tcp",
            "connected_at": datetime.now(timezone.utc).isoformat(),
            "bytes": 0,
        }
        log_activity("connection", f"اتصال Shadowsocks-TCP جدید از {ip} (کانفیگ {link.get('label','?')})", "info")

        first_payload = chunks[0]
        address, port, hlen = parse_socks5_addr(first_payload)
        initial_data = first_payload[hlen:]
        extra_chunks = chunks[1:]

        if not await check_and_use(uuid, len(raw)):
            writer.close()
            return
        stats["total_requests"] += 1
        logger.info(f"➡️  [{conn_id}] SS-TCP → {address}:{port}")

        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )
        _tune_socket(target_writer)

        if initial_data:
            target_writer.write(initial_data)
        for c in extra_chunks:
            if c:
                target_writer.write(c)
        if initial_data or extra_chunks:
            await target_writer.drain()

        gate_up = _QuotaGate(uuid)
        gate_down = _QuotaGate(uuid)
        conn = connections.get(conn_id)

        async def client_to_target():
            try:
                while True:
                    data = await reader.read(RELAY_BUF)
                    if not data:
                        break
                    stream.feed(data)
                    try:
                        payloads = list(stream.try_decrypt_chunks())
                    except ValueError:
                        break
                    for payload in payloads:
                        if not payload:
                            continue
                        if not await gate_up.add(len(payload)):
                            return
                        if conn is not None:
                            conn["bytes"] += len(payload)
                        target_writer.write(payload)
                    if target_writer.transport.get_write_buffer_size() > WRITE_HIGH_WATER:
                        await target_writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            finally:
                await gate_up.flush()
                try:
                    target_writer.write_eof()
                except Exception:
                    pass

        async def target_to_client():
            try:
                while True:
                    data = await target_reader.read(RELAY_BUF)
                    if not data:
                        break
                    if not await gate_down.add(len(data)):
                        return
                    if conn is not None:
                        conn["bytes"] += len(data)
                    writer.write(stream.encrypt_chunk(data))
                    if writer.transport.get_write_buffer_size() > WRITE_HIGH_WATER:
                        await writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            finally:
                await gate_down.flush()
                try:
                    writer.close()
                except Exception:
                    pass

        t1 = asyncio.create_task(client_to_target())
        t2 = asyncio.create_task(target_to_client())
        try:
            done, _ = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
            if t1.done() and not t1.exception() and not t2.done():
                # EOF ورودی کلاینت — پاسخ مقصد تا ۳۰۰ ثانیه دیگر فرصت دارد
                await asyncio.wait({t2}, timeout=300)
        finally:
            for t in (t1, t2):
                if not t.done():
                    t.cancel()
                    try:
                        await t
                    except (asyncio.CancelledError, Exception):
                        pass

        asyncio.create_task(schedule_save())

    except asyncio.TimeoutError:
        stats["total_errors"] += 1
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": f"ss-tcp: {exc}", "time": datetime.now().isoformat()})
        logger.error(f"SS-TCP [{conn_id}] error: {exc}")
    finally:
        try:
            writer.close()
        except Exception:
            pass
        connections.pop(conn_id, None)


async def _match(raw: bytes):
    """تطبیق بایت‌های اول اتصال با لینک‌های shadowsocks فعال (نسخه‌ی سازگار با TCP).
    برخلاف نسخه‌ی WS، خطای AEAD وسط استریم را نادیده می‌گیرد تا فقط تطبیق کامل
    اولین چانک ملاک باشد."""
    from protocol.shadowsocks.shadowsocks import CIPHERS, DEFAULT_CIPHER, derive_key
    async with LINKS_LOCK:
        candidates = [
            (uid, d) for uid, d in LINKS.items()
            if d.get("protocol") in ("shadowsocks", "shadowsocks-tcp") and is_link_allowed(d)
        ]
    for uid, d in candidates:
        cipher_name = d.get("ss_cipher", DEFAULT_CIPHER)
        info = CIPHERS.get(cipher_name)
        if not info:
            continue
        master_key = derive_key(d.get("ss_password", ""), info["key_len"])
        stream = _AEADStream(master_key, cipher_name)
        stream.feed(raw)
        try:
            chunks = list(stream.try_decrypt_chunks())
        except ValueError:
            continue
        if chunks and chunks[0]:
            return uid, stream, chunks
    return None


async def start_server(port: int, host: str = "0.0.0.0"):
    server = await asyncio.start_server(_handle_conn, host, port)
    logger.info(f"✅ Shadowsocks-TCP server روی پورت {port} بالا آمد")
    return server


async def stop_server(server):
    if server is not None:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass

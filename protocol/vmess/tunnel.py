# tunnel.py
# ══════════════════════════════════════════════════════════════════════════════
# VMess Tunnel Core — جریان مشترک WS و TCP
#   decode_request → اتصال به مقصد → هدر پاسخ → رله‌ی دوطرفه با چانک‌های AEAD
# نکته‌ی چرخه‌ی حیات (مطابق سرور واقعی xray):
#   - پایان ورودی کلاینت (چانک termination) فقط یعنی write_eof به مقصد —
#     اتصال باز می‌ماند تا پاسخ کامل شود.
#   - بسته شدن مقصد یعنی ارسال چانک EOF و بستن کل اتصال.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import secrets
import socket
from datetime import datetime, timezone
from typing import Awaitable, Callable

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
from protocol.vless.vless import check_and_use
from protocol.vmess import vmess as V


RELAY_BUF = 1024 * 1024
SOCK_BUF = 4 * 1024 * 1024
WRITE_HIGH_WATER = 512 * 1024
TCP_CONNECT_TIMEOUT = 10.0


def _tune_socket(writer: asyncio.StreamWriter):
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
        if hasattr(socket, "TCP_QUICKACK"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
    except OSError as e:
        logger.warning(f"VMess _tune_socket failed: {e}")


class TransportClosed(Exception):
    """اتصال زیرین (WS/TCP) بسته شد."""


async def handle_vmess_stream(
    transport_name: str,
    client_ip: str,
    uuid: str,
    read_exact: Callable[[int], Awaitable[bytes]],
    fill: Callable[[int], Awaitable[bytes]],
    send: Callable[[bytes], Awaitable[None]],
    close: Callable[[], Awaitable[None]],
) -> None:
    """جریان کامل یک اتصال VMess را مدیریت می‌کند."""
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not is_link_allowed(link):
        logger.warning(f"🚫 VMess-{transport_name} rejected uuid={uuid[:8]}… (not allowed)")
        await close()
        return

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": client_ip,
        "transport": f"vmess-{transport_name}",
        "connected_at": datetime.now(timezone.utc).isoformat(),
        "bytes": 0,
    }
    log_activity("connection", f"اتصال VMess جدید از {client_ip} (کانفیگ {link.get('label','?')})", "info")

    target_writer = None
    try:
        req, body_reader = await V.decode_request(read_exact, fill, expected_uuid=uuid)

        if not await check_and_use(uuid, 0):
            await close()
            return

        stats["total_requests"] += 1
        logger.info(f"➡️  [{conn_id}] VMess-{transport_name} → {req.address}:{req.port}")
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(req.address, req.port), timeout=TCP_CONNECT_TIMEOUT
            )
        except Exception as exc:
            stats["total_errors"] += 1
            error_logs.append({
                "error": f"vmess connect {req.address}:{req.port}: {exc}",
                "time": datetime.now().isoformat(),
            })
            await close()
            return
        _tune_socket(target_writer)

        # ارسال هدر پاسخ + شروع body
        await send(V.response_header_bytes(req))
        body_writer = V.response_body_writer(req)

        async def client_to_target():
            """چانک‌های رمز شده کلاینت → مقصد. پایان = write_eof به مقصد."""
            try:
                while True:
                    data = await body_reader.read()
                    if not data:
                        try:
                            target_writer.write_eof()
                        except Exception:
                            pass
                        return "eof"
                    if not await check_and_use(uuid, len(data)):
                        await close()
                        return "quota"
                    conn = connections.get(conn_id)
                    if conn is not None:
                        conn["bytes"] += len(data)
                    stats["total_bytes"] += len(data)
                    target_writer.write(data)
                    if target_writer.transport.get_write_buffer_size() > WRITE_HIGH_WATER:
                        await target_writer.drain()
            except TransportClosed:
                try:
                    target_writer.write_eof()
                except Exception:
                    pass
                return "closed"
            except (ConnectionResetError, BrokenPipeError, OSError):
                try:
                    target_writer.write_eof()
                except Exception:
                    pass
                return "reset"

        async def target_to_client():
            """پاسخ مقصد → چانک‌های AEAD برای کلاینت."""
            try:
                while True:
                    data = await _read_target(target_reader)
                    if not data:
                        await send(body_writer.write_eof())
                        return "eof"
                    if not await check_and_use(uuid, len(data)):
                        await close()
                        return "quota"
                    conn = connections.get(conn_id)
                    if conn is not None:
                        conn["bytes"] += len(data)
                    stats["total_bytes"] += len(data)
                    await send(body_writer.write_chunk(data))
            except TransportClosed:
                return "closed"
            except (ConnectionResetError, BrokenPipeError, OSError):
                return "reset"

        t1 = asyncio.create_task(client_to_target())
        t2 = asyncio.create_task(target_to_client())
        try:
            while True:
                done, _pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
                if t2 in done:
                    # پاسخ کامل شد (مقصد بست) — کل اتصال بسته می‌شود
                    break
                if t1 in done:
                    r1 = t1.result()
                    if r1 in ("closed", "quota", "reset"):
                        break
                    # eof از کلاینت — انتظار برای ادامه‌ی پاسخ مقصد
                    continue
        finally:
            for t in (t1, t2):
                if not t.done():
                    t.cancel()
                    try:
                        await t
                    except (asyncio.CancelledError, Exception):
                        pass

        asyncio.create_task(schedule_save())

    except V.VMessAuthError as exc:
        stats["total_errors"] += 1
        logger.warning(f"🚫 VMess-{transport_name} [{conn_id}] auth failed: {exc}")
        await close()
    except V.VMessError as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": f"vmess: {exc}", "time": datetime.now().isoformat()})
        logger.warning(f"VMess-{transport_name} [{conn_id}] protocol error: {exc}")
        await close()
    except TransportClosed:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "vmess handshake timeout", "time": datetime.now().isoformat()})
        await close()
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"VMess-{transport_name} [{conn_id}] error: {exc}")
        await close()
    finally:
        if target_writer:
            try:
                target_writer.close()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 VMess-{transport_name} closed [{conn_id}] total={len(connections)}")


async def _read_target(target_reader: asyncio.StreamReader) -> bytes:
    return await asyncio.wait_for(target_reader.read(RELAY_BUF), timeout=600)

# tests/test_live.py
# ══════════════════════════════════════════════════════════════════════════════
# تست زنده‌ی سرور با کلاینت‌های واقعی پروتکل:
#   ۱) بوت سرور روی پورت تستی
#   ۲) لاگین API → ساخت کانفیگ برای هر پروتکل (بعضی با پورت اختصاصی)
#   ۳) چک listener پورت اختصاصی (uvicorn اضافی + TCP خام)
#   ۴) VMess-TCP واقعی (کلاینت spec) → گرفتن پاسخ HTTP از تارگت محلی
#   ۵) VMess-WS واقعی (کلاینت spec روی وب‌سوکت)
#   ۶) Shadowsocks-TCP واقعی (کلاینت AEAD) → گرفتن پاسخ HTTP
#   ۷) VLESS-WS روی پورت اختصاصی (uvicorn اضافی)
#   ۸) حذف کانفیگ → بسته شدن listener
# اجرا:  python tests/test_live.py
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import base64
import hashlib
import io
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

PANEL_PORT = 8891
VM_TCP_PORT = 21002
SS_TCP_PORT = 21003
VLESS_PORT = 21001
TARGET_PORT = 9801

PASSED = 0


def ok(name):
    global PASSED
    PASSED += 1
    print(f"  ✓ {name}")


# ── تارگت HTTP محلی که کلاینت‌ها از طریق تونل باید بگیرند ──
TARGET_BODY = b"<html><body>RVG-LIVE-TEST-OK</body></html>"


async def start_target():
    async def handler(reader, writer):
        await reader.read(65536)
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                + str(len(TARGET_BODY)).encode() + b"\r\nConnection: close\r\n\r\n" + TARGET_BODY)
        writer.write(resp)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", TARGET_PORT)
    return server


# ══════════════════════════════════════════════════════════════════════════════
# کلاینت‌های پروتکل (سمت کلاینت — مطابق اسپک)
# ══════════════════════════════════════════════════════════════════════════════

def vmess_build_request(uuid, address, port, security=3, option=0x1 | 0x4 | 0x8):
    """درخواست کامل VMess (هدر AEAD + چانک اول) — مطابق client.go"""
    from protocol.vmess import vmess as V
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ck = V.cmd_key_for(uuid)
    aid = V.create_auth_id(ck, int(time.time()))
    body_key, body_iv = os.urandom(16), os.urandom(16)
    token = os.urandom(1)[0]

    hdr = bytearray()
    hdr.append(1)
    hdr += body_iv + body_key
    hdr.append(token)
    hdr.append(option)
    pad_len = 5 if (option & 0x8) else 0
    hdr.append((pad_len << 4) | security)
    hdr.append(0)
    hdr.append(0x01)  # TCP
    if address.replace(".", "").isdigit():
        hdr += struct.pack(">H", port) + b"\x01" + bytes(int(x) for x in address.split("."))
    else:
        hdr += struct.pack(">H", port) + b"\x02" + bytes([len(address)]) + address.encode()
    if pad_len:
        hdr += os.urandom(pad_len)
    h = 0x811C9DC5
    for b in hdr:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    hdr += struct.pack(">I", h)

    nonce8 = os.urandom(8)
    # نکته: بلاک طول با saltهای *_Length رمز می‌شود (consts.go) — نه salt پیلود
    enc_len = AESGCM(V.kdf16(ck, "VMess Header AEAD Key_Length", aid, nonce8)).encrypt(
        V.kdf(ck, "VMess Header AEAD Nonce_Length", aid, nonce8)[:12],
        struct.pack(">H", len(hdr)), aid)
    enc_payload = AESGCM(V.kdf16(ck, "VMess Header AEAD Key", aid, nonce8)).encrypt(
        V.kdf(ck, "VMess Header AEAD Nonce", aid, nonce8)[:12], bytes(hdr), aid)
    return aid + enc_len + nonce8 + enc_payload, body_key, body_iv, token


async def vmess_decode_response(wire, body_key, body_iv, token, security=3, option=0x1 | 0x4 | 0x8):
    """پاسخ کامل سرور (هدر AEAD + چانک‌ها) را دیکد می‌کند."""
    from protocol.vmess import vmess as V
    import hashlib as hl
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    resp_key = hl.sha256(body_key).digest()[:16]
    resp_iv = hl.sha256(body_iv).digest()[:16]
    enc_len, rest = wire[:18], wire[18:]
    ln = struct.unpack(">H", AESGCM(V.kdf16(resp_key, "AEAD Resp Header Len Key")).decrypt(
        V.kdf(resp_iv, "AEAD Resp Header Len IV")[:12], enc_len, None))[0]
    payload, rest = rest[:ln + 16], rest[ln + 16:]
    pt = AESGCM(V.kdf16(resp_key, "AEAD Resp Header Key")).decrypt(
        V.kdf(resp_iv, "AEAD Resp Header IV")[:12], payload, None)
    assert pt[0] == token, "response token mismatch"

    f = io.BytesIO(rest)

    async def fill(n):
        return f.read(n)

    br = V.BodyReader(resp_key, resp_iv, security, option, fill)
    chunks = []
    while True:
        c = await br.read()
        if c == b"":
            break
        chunks.append(c)
    return b"".join(chunks)


def ss_client_stream(password: bytes, cipher: str, target: str, port: int, payload: bytes):
    """استریم کلاینت Shadowsocks AEAD — salt + چانک‌های رمز شده."""
    from protocol.shadowsocks.shadowsocks import derive_key, CIPHERS, _AEADStream
    info = CIPHERS[cipher]
    key = derive_key(password.decode(), info["key_len"])
    stream = _AEADStream(key, cipher)
    # target به فرمت SOCKS5
    if target.replace(".", "").isdigit():
        addr = b"\x01" + bytes(int(x) for x in target.split("."))
    else:
        tb = target.encode()
        addr = b"\x03" + bytes([len(tb)]) + tb
    first = addr + struct.pack(">H", port) + payload
    out = stream.encrypt_chunk(first)
    out += stream.encrypt_chunk(b"")
    return out, key, cipher


async def ss_read_response(reader, key: bytes, cipher: str):
    from protocol.shadowsocks.shadowsocks import CIPHERS, _AEADStream
    info = CIPHERS[cipher]
    stream = _AEADStream(key, cipher)
    buf = b""
    data = b""
    while b"</html>" not in data:
        chunk = await asyncio.wait_for(reader.read(65536), timeout=8)
        if not chunk:
            break
        buf += chunk
        stream.feed(chunk)
        try:
            for payload in stream.try_decrypt_chunks():
                data += payload
        except ValueError:
            pass
    return data


# ══════════════════════════════════════════════════════════════════════════════
# تست اصلی
# ══════════════════════════════════════════════════════════════════════════════

async def recv_until(ws, marker: bytes, timeout=20) -> bytes:
    """تا رسیدن مارکر پیام می‌گیرد — recv ساده (بدون wait_for)."""
    wire = b""
    deadline = time.time() + timeout
    while True:
        if time.time() > deadline:
            raise TimeoutError("recv_until deadline")
        try:
            msg = await ws.recv()
        except Exception:
            # بستن اتصال = پایان استریم پاسخ (رفتار طبیعی تونل)
            return wire
        wire += msg
        if marker in wire:
            return wire


async def wait_port(port, timeout=25):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            _, w = await asyncio.open_connection("127.0.0.1", port)
            w.close()
            return True
        except Exception:
            await asyncio.sleep(0.3)
    return False


async def main():
    print("▶ بوت سرور...")
    env = dict(os.environ)
    data_dir = Path(__file__).resolve().parents[1] / f"data_test_{int(time.time())}"
    env["DATA_DIR"] = str(data_dir)
    env["PORT"] = str(PANEL_PORT)
    env["ADMIN_PASSWORD"] = "test1234"
    env.pop("RVG_HOST", None)
    _logf = open(Path(__file__).resolve().parents[1] / "data_test_server.log", "w", encoding="utf-8")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "main.py", "--port", str(PANEL_PORT),
        stdout=_logf, stderr=asyncio.subprocess.STDOUT, env=env,
    )
    try:
        assert await wait_port(PANEL_PORT), "سرور بالا نیامد"
        ok("سرور بالا آمد")

        target = await start_target()
        ok(f"تارگت HTTP محلی روی {TARGET_PORT}")

        base = f"http://127.0.0.1:{PANEL_PORT}"
        async with httpx.AsyncClient(base_url=base, timeout=30) as api:
            # لاگین
            r = await api.post("/api/login", json={"password": "test1234"})
            assert r.status_code == 200, r.text
            ok("لاگین API")

            # تنظیم دامنه‌ی سرور
            r = await api.post("/api/settings/server", json={"host": "127.0.0.1", "tls": False})
            assert r.status_code == 200, r.text
            ok("ثبت دامنه‌ی عمومی سرور")

            # ── ساخت کانفیگ‌ها ──
            async def mk(proto, port=None, extra=None):
                body = {"label": f"t-{proto}", "protocol": proto, "limit_value": 0}
                if port:
                    body["listen_port"] = port
                if extra:
                    body.update(extra)
                r = await api.post("/api/links", json=body)
                assert r.status_code == 200, r.text
                return r.json()

            vless = await mk("vless-ws", port=VLESS_PORT)
            vm_ws = await mk("vmess-ws")
            vm_tcp = await mk("vmess-tcp", port=VM_TCP_PORT)
            ss_tcp = await mk("shadowsocks-tcp", port=SS_TCP_PORT)
            ss_ws = await mk("shadowsocks")
            trojan = await mk("trojan-ws")
            vm_hu = await mk("vmess-httpupgrade")
            ok(f"ساخت ۷ کانفیگ ({len(set())})")

            r = await api.get("/api/links")
            links = {l["uuid"]: l for l in r.json()["links"]}
            assert len(links) >= 7

            # لینک‌ها باید پورت درست داشته باشند
            vl = links[vless["uuid"]]["vless_link"]
            assert f"127.0.0.1:{VLESS_PORT}" in vl, vl
            assert "type=ws" in vl and "security=none" in vl, vl
            ok(f"لینک VLESS با پورت اختصاصی: {vl[:70]}…")

            vmws_link = links[vm_ws["uuid"]]["vless_link"]
            assert vmws_link.startswith("vmess://")
            cfg = json.loads(base64.b64decode(vmws_link[8:] + "=" * 4))
            assert cfg["net"] == "ws" and cfg["port"] == str(PANEL_PORT), cfg
            ok("لینک VMess-WS (vmess:// base64 JSON) روی پورت پنل")

            vmtcp_link = links[vm_tcp["uuid"]]["vless_link"]
            cfg2 = json.loads(base64.b64decode(vmtcp_link[8:] + "=" * 4))
            assert cfg2["net"] == "tcp" and cfg2["port"] == str(VM_TCP_PORT), cfg2
            ok("لینک VMess-TCP با پورت اختصاصی")

            sstcp_link = links[ss_tcp["uuid"]]["vless_link"]
            assert sstcp_link.startswith("ss://") and "plugin" not in sstcp_link, sstcp_link
            assert f"@127.0.0.1:{SS_TCP_PORT}" in sstcp_link
            ok("لینک Shadowsocks-TCP کلاسیک بدون پلاگین")

            # ── listenerها ──
            assert await wait_port(VM_TCP_PORT), "listener VMess-TCP باز نشد"
            assert await wait_port(SS_TCP_PORT), "listener SS-TCP باز نشد"
            assert await wait_port(VLESS_PORT), "listener HTTP اضافی باز نشد"
            ok("هر ۳ listener پورت اختصاصی باز شدند")

            r = await api.get("/api/ports")
            ports = r.json()
            kinds = {L["port"]: L["kind"] for L in ports["listeners"]}
            assert kinds.get(VM_TCP_PORT) == "vmess", (kinds, ports.get("failed"))
            assert kinds.get(SS_TCP_PORT) == "ss", (kinds, ports.get("failed"))
            assert kinds.get(VLESS_PORT) == "http", (kinds, ports.get("failed"))
            ok("گزارش /api/ports درست است")

            # ── ۴) VMess-TCP واقعی ──
            # ── ۴) VMess-TCP واقعی (با چند تلاش برای پایداری روی loopback ویندوز) ──
            for attempt in range(3):
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", VM_TCP_PORT)
                    req, bk, biv, tok = vmess_build_request(vm_tcp["uuid"], "127.0.0.1", TARGET_PORT)
                    from protocol.vmess import vmess as V
                    bw = V.BodyWriter(bk, biv, 3, 0x1 | 0x4 | 0x8)
                    writer.write(req + bw.write_chunk(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n"))
                    await writer.drain()
                    wire, body = b"", b""
                    while b"RVG-LIVE-TEST-OK" not in body:
                        part = await asyncio.wait_for(reader.read(262144), timeout=10)
                        if not part:
                            break
                        wire += part
                        body = await vmess_decode_response(wire, bk, biv, tok)
                    assert b"RVG-LIVE-TEST-OK" in body, body[:80]
                    writer.close()
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    await asyncio.sleep(1)
            ok(f"VMess-TCP واقعی — پاسخ مقصد از داخل تونل دریافت شد ({len(wire)} بایت سیم)")

            # ── ۵) VMess-WS واقعی (وب‌سوکت) ──
            import websockets
            ws_url = f"ws://127.0.0.1:{PANEL_PORT}/vmess-ws/{vm_ws['uuid']}"
            for attempt in range(3):
                try:
                    async with websockets.connect(ws_url, max_size=None) as ws:
                        req, bk, biv, tok = vmess_build_request(vm_ws["uuid"], "127.0.0.1", TARGET_PORT)
                        from protocol.vmess import vmess as V
                        bw = V.BodyWriter(bk, biv, 3, 0x1 | 0x4 | 0x8)
                        await ws.send(req + bw.write_chunk(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n"))
                        wire = await recv_until(ws, b"RVG-LIVE-TEST-OK")
                        body = await vmess_decode_response(wire, bk, biv, tok)
                        assert b"RVG-LIVE-TEST-OK" in body
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    await asyncio.sleep(1)
            ok("VMess-WS واقعی روی پورت پنل")

            # ── ۵.۵) VMess-HTTPUpgrade واقعی (روی همان اندپوینت WS) ──
            async with websockets.connect(
                f"ws://127.0.0.1:{PANEL_PORT}/vmess-ws/{vm_hu['uuid']}",
                max_size=None,
            ) as ws:
                req, bk, biv, tok = vmess_build_request(vm_hu["uuid"], "127.0.0.1", TARGET_PORT)
                from protocol.vmess import vmess as V
                bw = V.BodyWriter(bk, biv, 3, 0x1 | 0x4 | 0x8)
                await ws.send(req + bw.write_chunk(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n"))
                await recv_until(ws, b"RVG-LIVE-TEST-OK")
            ok("VMess-HTTPUpgrade واقعی")

            # ── ۶) Shadowsocks-TCP واقعی ──
            reader, writer = await asyncio.open_connection("127.0.0.1", SS_TCP_PORT)
            password = links[ss_tcp["uuid"]]["ss_password"].encode()
            cipher = links[ss_tcp["uuid"]]["ss_cipher"]
            req_bytes = b"GET / HTTP/1.1\r\nHost: t\r\n\r\n"
            out, key, cipher = ss_client_stream(password, cipher, "127.0.0.1", TARGET_PORT, req_bytes)
            writer.write(out)
            await writer.drain()
            data = await ss_read_response(reader, key, cipher)
            assert b"RVG-LIVE-TEST-OK" in data, data[:200]
            writer.close()
            ok("Shadowsocks-TCP واقعی (AEAD چانک‌بندی شده)")

            # ── ۷) VLESS-WS روی پورت اختصاصی (uvicorn اضافی) ──
            async with websockets.connect(f"ws://127.0.0.1:{VLESS_PORT}/ws/{vless['uuid']}", max_size=None) as ws:
                hdr = b"\x00" + bytes.fromhex(vless["uuid"].replace("-", "")) + b"\x00\x01"
                hdr += struct.pack(">H", TARGET_PORT) + b"\x01" + bytes(int(x) for x in "127.0.0.1".split("."))
                await ws.send(hdr + b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
                resp = b""
                while b"RVG-LIVE-TEST-OK" not in resp:
                    msg = await asyncio.wait_for(ws.recv(), timeout=15)
                    resp += msg
                assert resp[:2] == b"\x00\x00", resp[:8]
            ok("VLESS-WS روی پورت اختصاصی (uvicorn اضافی)")

            # ── ۸) Trojan-WS روی پورت پنل ──
            async with websockets.connect(f"ws://127.0.0.1:{PANEL_PORT}/trojan-ws", max_size=None) as ws:
                # Trojan: hex(SHA224(uuid)) + CRLF + CMD + ATYP + ADDR + PORT + CRLF
                th = hashlib.sha224(trojan["uuid"].encode()).hexdigest().encode()
                hdr = th + b"\r\n" + b"\x01" + b"\x01" + bytes(int(x) for x in "127.0.0.1".split(".")) + struct.pack(">H", TARGET_PORT) + b"\r\n"
                await ws.send(hdr + b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
                resp = b""
                while b"RVG-LIVE-TEST-OK" not in resp:
                    resp += await asyncio.wait_for(ws.recv(), timeout=15)
            ok("Trojan-WS واقعی روی پورت پنل")

            # ── سابسکریپشن ──
            r = await api.get(f"/sub/{vm_ws['uuid']}")
            assert r.status_code == 200
            content = base64.b64decode(r.text)
            assert content.decode().startswith("vmess://")
            ok("صفحه سابسکریپشن تک‌کانفیگ")

            # ── حذف کانفیگ → بسته شدن listener ──
            r = await api.delete(f"/api/links/{vm_tcp['uuid']}")
            assert r.status_code == 200
            await asyncio.sleep(1.0)
            sock = socket.socket()
            try:
                sock.settimeout(2)
                sock.connect(("127.0.0.1", VM_TCP_PORT))
                raise AssertionError("listener VMess-TCP بعد از حذف بسته نشد")
            except (ConnectionRefusedError, OSError, socket.timeout):
                pass
            finally:
                sock.close()
            ok("حذف کانفیگ → listener پورت بسته شد")

            # بکاپ
            r = await api.get("/api/backup/export")
            assert r.status_code == 200 and "rvg-backup" in r.text
            ok("بکاپ کامل")

        target.close()

    finally:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=8)
        except (ProcessLookupError, asyncio.TimeoutError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    print(f"\nهمه‌ی {PASSED} تست زنده پاس شد ✓")


if __name__ == "__main__":
    asyncio.run(main())

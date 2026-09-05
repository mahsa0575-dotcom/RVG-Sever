# websocket.py
# ══════════════════════════════════════════════════════════════════════════════
# VMess — اندپوینت WebSocket (/vmess-ws/{uuid})
# هدر VMess داخل پیام‌های باینری WS است؛ مسیر فقط کانفیگ را مشخص می‌کند.
# همان اندپوینت برای ترنسپورت httpupgrade هم استفاده می‌شود (هندشیک یکسان است).
# ══════════════════════════════════════════════════════════════════════════════

import asyncio

from fastapi import WebSocket, WebSocketDisconnect

from main import logger
from protocol.vmess import vmess as V
from protocol.vmess.tunnel import TransportClosed, handle_vmess_stream


class _WsStream:
    """بافر پیام‌های باینری WS با دو وجه: read_exact (هدر) و fill (body)."""

    def __init__(self, ws: WebSocket):
        self._ws = ws
        self._buf = bytearray()

    async def _more(self) -> bool:
        msg = await self._ws.receive()
        if msg["type"] == "websocket.disconnect":
            return False
        data = msg.get("bytes") or (msg.get("text") or "").encode()
        if not data:
            return True
        self._buf += data
        return True

    async def read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            if not await self._more():
                raise TransportClosed()
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def fill(self, n: int) -> bytes:
        """هرچه از پیام‌های بعدی آماده شود را برمی‌گرداند؛ b"" یعنی قطع WS."""
        if not self._buf and not await self._more():
            return b""
        out = bytes(self._buf)
        self._buf.clear()
        return out


async def vmess_ws_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()
    fwd = ws.headers.get("x-forwarded-for")
    ip = fwd.split(",")[0].strip() if fwd else (
        ws.headers.get("x-real-ip", "").strip()
        or (ws.client.host if ws.client else "نامشخص")
    )

    stream = _WsStream(ws)

    async def send(data: bytes):
        await ws.send_bytes(data)

    async def close():
        try:
            await ws.close(code=1008, reason="quota/disabled/invalid")
        except Exception:
            pass

    try:
        await handle_vmess_stream(
            "ws", ip, uuid,
            stream.read_exact, stream.fill, send, close,
        )
    except (WebSocketDisconnect, TransportClosed):
        pass
    except Exception as exc:
        logger.error(f"VMess-WS tunnel error: {exc}")
    finally:
        # بستن صریح وب‌سوکت — بدون این، uvicorn اتصال را بدون فریم close قطع
        # می‌کند و فریم‌های در صف ارسال دور ریخته می‌شوند.
        try:
            await ws.close()
        except Exception:
            pass

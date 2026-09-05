# tcp_server.py
# ══════════════════════════════════════════════════════════════════════════════
# VMess — سرور TCP خام (ترنسپورت tcp) — یک سرور asyncio به‌ازای هر کانفیگ که
# پورت اختصاصی خودش را دارد. توسط port_manager بالا آورده/بسته می‌شود.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio

from main import logger
from protocol.vmess import vmess as V
from protocol.vmess.tunnel import TransportClosed, handle_vmess_stream


async def _handle_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       uuid: str):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "نامشخص"

    async def read_exact(n: int) -> bytes:
        return await reader.readexactly(n)

    async def fill(n: int) -> bytes:
        return await reader.read(n)

    async def send(data: bytes):
        writer.write(data)
        await writer.drain()

    async def close():
        try:
            writer.close()
        except Exception:
            pass

    try:
        await handle_vmess_stream(
            "tcp", ip, uuid,
            read_exact, fill, send, close,
        )
    except (asyncio.IncompleteReadError, TransportClosed, ConnectionResetError):
        pass
    except Exception as exc:
        logger.error(f"VMess-TCP conn error: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_server(uuid: str, port: int, host: str = "0.0.0.0"):
    """سرور VMess-TCP را روی پورت داده‌شده بالا می‌آورد و Server را برمی‌گرداند."""
    V.register_user(uuid)

    async def handler(r, w):
        await _handle_conn(r, w, uuid)

    server = await asyncio.start_server(handler, host, port)
    logger.info(f"✅ VMess-TCP server برای {uuid[:8]}… روی پورت {port} بالا آمد")
    return server


async def stop_server(server, uuid: str):
    V.unregister_user(uuid)
    if server is not None:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass

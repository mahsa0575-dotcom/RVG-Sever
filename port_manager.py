# port_manager.py
# ══════════════════════════════════════════════════════════════════════════════
# مدیریت پورت‌های اختصاصی روی VPS
#
# هر کانفیگ می‌تواند پورت اختصاصی خودش را داشته باشد (فیلد listen_port):
#   - vmess-tcp / shadowsocks-tcp  → سرور TCP خام اختصاصی (پروتکل یک کانفیگ)
#   - بقیه‌ی ترنسپورت‌های HTTP (ws/xhttp/httpupgrade) → یک uvicorn اضافی روی آن
#     پورت بالا می‌آید که همان اپ FastAPI را سرو می‌کند (مسیرها همان‌اند).
#   - mtproto → پروسه‌ی مستقل خودش را دارد (mtproto_native) و مستقل از این ماژول است.
#
# پورت ۰ یعنی «روی پورت خود پنل» (فقط برای ترنسپورت‌های HTTP معنا دارد).
# همه‌ی listenerها بعد از ری‌استارت از روی state بازسازی می‌شوند.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import logging
import socket
from typing import Optional

logger = logging.getLogger("RVG-Gateway")

# پورت‌های uvicorn اضافی (ترنسپورت HTTP) — هر پورت فقط یک بار
_uvicorn_servers: dict[int, object] = {}
# سرورهای TCP خام: پورت → ("vmess", uuid) | ("ss", None)
_tcp_servers: dict[int, dict] = {}
_tcp_lock = asyncio.Lock()
_uvi_lock = asyncio.Lock()

# خطای آخرین تلاش برای هر پورت — برای نمایش در داشبورد
port_errors: dict[int, str] = {}

# ── رجیستری تسک‌های بک‌گراند ──
# نکته‌ی حیاتی پایتون: خروجی asyncio.create_task باید یک جا نگه داشته شود وگرنه
# تسک وسط اجرا توسط GC جمع می‌شود (باعث می‌شد listener بالا بیاید ولی رجیستر نشود).
_bg_tasks: set = set()


def spawn(coro) -> asyncio.Task:
    """create_task با نگه‌داشتن رفرنس — برای همه‌ی کارهای پس‌زمینه."""
    t = asyncio.create_task(coro)
    _bg_tasks.add(t)
    t.add_done_callback(_bg_tasks.discard)
    return t


def _port_free(port: int, host: str = "0.0.0.0") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def is_port_listening(port: int) -> bool:
    """آیا این پورت توسط همین پروسه مدیریت شده؟"""
    return port in _uvicorn_servers or port in _tcp_servers


async def _start_uvicorn_port(port: int, app, host: str = "0.0.0.0") -> bool:
    """یک uvicorn.Server اضافی روی پورت داده‌شده بالا می‌آورد (همان اپ)."""
    import uvicorn
    async with _uvi_lock:
        if port in _uvicorn_servers:
            return True
        if not _port_free(port):
            port_errors[port] = f"پورت {port} اشغال است"
            logger.error(f"پورت {port} آزاد نیست — listener بالا نمی‌آید")
            return False
        try:
            config = uvicorn.Config(
                app, host=host, port=port,
                log_level="warning",
                loop="auto", http="auto", lifespan="off",
                ws="auto",
            )
            server = uvicorn.Server(config)

            async def _serve_safe():
                # uvicorn در شکست bind با sys.exit خارج می‌شود؛ SystemExit داخل
                # تسک در uvloop کل loop را می‌کشد — اینجا خنثی می‌شود.
                try:
                    await server.serve()
                except SystemExit as e:
                    logger.warning(f"uvicorn پورت {port}: خروج ({e.code})")
                except BaseException as e:
                    logger.warning(f"uvicorn پورت {port}: {e}")

            # ثبت فوری — اگر بلافاصله مرد، پایین‌تر از رجیستری حذف می‌شود
            task = spawn(_serve_safe())
            _uvicorn_servers[port] = server
            port_errors.pop(port, None)
            await asyncio.sleep(0.6)
            if task.done() and not server.started:
                _uvicorn_servers.pop(port, None)
                raise RuntimeError("uvicorn بلافاصله متوقف شد")
            logger.info(f"🌐 HTTP listener روی پورت {port} بالا آمد")
            return True
        except Exception as exc:
            port_errors[port] = str(exc)[:160]
            _uvicorn_servers.pop(port, None)
            logger.error(f"شکست در بالا آوردن HTTP listener روی پورت {port}: {exc}")
            return False


async def _stop_uvicorn_port(port: int) -> bool:
    async with _uvi_lock:
        server = _uvicorn_servers.pop(port, None)
        if server is None:
            return False
        try:
            server.should_exit = True
        except Exception:
            pass
        logger.info(f"🌐 HTTP listener پورت {port} بسته شد")
        return True


async def _start_tcp_port(port: int, kind: str, uuid: str = "", host: str = "0.0.0.0") -> bool:
    """سرور TCP خام برای یک کانفیگ."""
    async with _tcp_lock:
        if port in _tcp_servers:
            return True
        if not _port_free(port):
            port_errors[port] = f"پورت {port} اشغال است"
            logger.error(f"پورت {port} آزاد نیست — سرور {kind} بالا نمی‌آید")
            return False
        try:
            if kind == "vmess":
                from protocol.vmess import tcp_server as vt
                server = await vt.start_server(uuid, port, host)
            elif kind == "ss":
                from protocol.shadowsocks import tcp_server as st
                server = await st.start_server(port, host)
            else:
                raise ValueError(f"unknown tcp kind {kind}")
            _tcp_servers[port] = {"kind": kind, "uuid": uuid, "server": server}
            port_errors.pop(port, None)
            return True
        except Exception as exc:
            port_errors[port] = str(exc)[:160]
            logger.error(f"شکست در بالا آوردن سرور {kind} روی پورت {port}: {exc}")
            return False


async def _stop_tcp_port(port: int) -> bool:
    async with _tcp_lock:
        entry = _tcp_servers.pop(port, None)
        if entry is None:
            return False
        server = entry.get("server")
        if server is not None:
            server.close()
            try:
                await server.wait_closed()
            except Exception:
                pass
        logger.info(f"سرور {entry.get('kind')} پورت {port} بسته شد")
        return True


def needs_own_port(protocol: str) -> bool:
    """پروتکل‌هایی که حتماً پورت اختصاصی TCP مستقل لازم دارند."""
    return protocol in ("vmess-tcp", "shadowsocks-tcp")


def tcp_kind(protocol: str) -> Optional[str]:
    if protocol == "vmess-tcp":
        return "vmess"
    if protocol == "shadowsocks-tcp":
        return "ss"
    return None


def sync_ports_for_link(link: dict, uid: str, app, panel_port: int):
    """همگام‌سازی listenerها با وضعیت یک کانفیگ — non-blocking."""
    spawn(_sync_link(link, uid, app, panel_port))


async def _sync_link(link: dict, uid: str, app, panel_port: int):
    if (link.get("core") or "unicorn") != "unicorn":
        return  # پورت‌های هسته‌های خارجی را خود هسته bind می‌کند
    proto = link.get("protocol", "")
    if proto == "mtproto":
        return  # پورت MTProto را باینری رسمی تلگرام bind می‌کند — دست نزن
    active = bool(link.get("active", True))
    port = int(link.get("listen_port") or 0)
    kind = tcp_kind(proto)
    logger.info(f"SYNC-PORT: uid={uid[:8]} proto={proto} port={port} kind={kind} active={active}")

    # پروتکل‌های TCP خام: پورت اجباری
    if kind:
        if active and port and port != panel_port:
            await _start_tcp_port(port, kind, uid)
        else:
            await _stop_tcp_port(port)
        return

    # ترنسپورت‌های HTTP: پورت اختیاری (۰ = پورت پنل)
    if port and port != panel_port:
        if active:
            await _start_uvicorn_port(port, app)
    # اگر هیچ کانفیگ دیگری این پورت را نیاز نداشت، ببند — از sync_all مدیریت می‌شود


async def sync_all(LINKS: dict, LINKS_LOCK: asyncio.Lock, app, panel_port: int):
    """بازسازی/تمیزکاری کامل listenerها مطابق state فعلی — بعد از startup یا
    تغییرات ساختاری صدا زده می‌شود."""
    needed_http: set[int] = set()
    needed_tcp: dict[int, tuple[str, str]] = {}

    async with LINKS_LOCK:
        snapshot = [(uid, dict(d)) for uid, d in LINKS.items()]

    for uid, d in snapshot:
        if not d.get("active", True):
            continue
        if (d.get("core") or "unicorn") != "unicorn":
            continue  # اینباند هسته‌ی خارجی — مدیریتش با core_manager است
        if d.get("protocol") == "mtproto":
            continue  # پورت MTProto را mtproto-native خودش bind می‌کند
        proto = d.get("protocol", "")
        port = int(d.get("listen_port") or 0)
        if not port or port == panel_port:
            continue
        kind = tcp_kind(proto)
        if kind:
            needed_tcp[port] = (kind, uid)
        else:
            needed_http.add(port)

    # بستن listenerهای بلااستفاده
    for port in list(_tcp_servers.keys()):
        if port not in needed_tcp:
            await _stop_tcp_port(port)
    for port in list(_uvicorn_servers.keys()):
        if port not in needed_http:
            await _stop_uvicorn_port(port)

    # روشن کردن موارد لازم
    for port, (kind, uid) in needed_tcp.items():
        await _start_tcp_port(port, kind, uid)
    for port in needed_http:
        await _start_uvicorn_port(port, app)


def listeners_status() -> list[dict]:
    out = []
    for port, server in sorted(_uvicorn_servers.items()):
        out.append({
            "port": port, "kind": "http", "uuid": "",
            "error": port_errors.get(port),
        })
    for port, entry in sorted(_tcp_servers.items()):
        out.append({
            "port": port, "kind": entry.get("kind"), "uuid": entry.get("uuid", ""),
            "error": port_errors.get(port),
        })
    return out


def failed_ports() -> list[dict]:
    """پورت‌هایی که تلاش شروع شد ولی ثبت نشدند (برای دیباگ داشبورد)."""
    registered = set(_uvicorn_servers) | set(_tcp_servers)
    return [
        {"port": port, "error": err}
        for port, err in sorted(port_errors.items())
        if port not in registered
    ]


def port_in_use_by_us(port: int) -> bool:
    return port in _uvicorn_servers or port in _tcp_servers


def find_free_port(start: int, end: int, exclude: Optional[set] = None) -> Optional[int]:
    """اولین پورت آزاد در بازه — هم از نظر همین پروسه هم از نظر سیستم‌عامل."""
    exclude = exclude or set()
    for port in range(start, end):
        if port in exclude or port_in_use_by_us(port):
            continue
        if _port_free(port):
            return port
    return None

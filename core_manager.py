# core_manager.py
# ══════════════════════════════════════════════════════════════════════════════
# مدیریت هسته‌های خارجی (Xray و sing-box)
#   - دانلود و نصب خودکار باینری‌های رسمی از GitHub Releases (لینوکس amd64/arm64)
#   - گزارش نسخه و وضعیت
#   - اجرای یک پروسه برای هر هسته با کل اینباندها (مثل 3x-ui/S-UI) + ری‌استارت
#
# روی ویندوز (محیط توسعه) باینری لینوکسی اجرا نمی‌شود — توابع install/run خودشان
# را با پیام واضح ناموفق اعلام می‌کنند و مابقی پنل مستقل کار می‌کند.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import json
import logging
import os
import platform
import shutil
import struct
import zipfile
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("RVG-Gateway")

DATA_DIR = Path(os.environ.get("DATA_DIR") or (Path(__file__).resolve().parent / "data"))
CORES_DIR = DATA_DIR / "cores"

XRAY_REPO = "XTLS/Xray-core"
SINGBOX_REPO = "SagerNet/sing-box"
# نسخه‌ی پین‌شده sing-box — 1.11 همه‌ی پروتکل‌ها (hysteria 1+2، tuic، reality) را دارد؛
# نسخه‌های 1.12+ پروتکل‌های قدیمی را حذف کرده‌اند و کانفیگ ما را رد می‌کنند.
SINGBOX_VERSION = "1.11.15"

_state = {
    # name → {"bin": Path|None, "version": str|None, "proc": asyncio.subprocess|None,
    #         "config_path": Path|None, "starting": bool}
}


def _arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "64"
    if m in ("aarch64", "arm64"):
        return "arm64-v8a"
    return m


# ── نصب ────────────────────────────────────────────────────────────────────────

async def _download(url: str, dest: Path):
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
        async with c.stream("GET", url) as r:
            r.raise_for_status()
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as f:
                async for chunk in r.aiter_bytes(1 << 16):
                    f.write(chunk)


def _gh_latest_asset(repo: str, needle: str) -> Optional[str]:
    """آخرین ریلیز رسمی را می‌گیرد و لینک asset شامل needle را برمی‌گرداند."""
    try:
        r = httpx.get(f"https://api.github.com/repos/{repo}/releases/latest", timeout=20)
        r.raise_for_status()
        for a in r.json().get("assets", []):
            name = a.get("name", "")
            if needle.lower() in name.lower() and name.endswith((".zip", ".tar.gz")):
                return a.get("browser_download_url")
    except Exception as exc:
        logger.warning(f"core_manager: گرفتن ریلیز {repo} ناموفق: {exc}")
    return None


def _core_dir(name: str) -> Path:
    return CORES_DIR / name


def _bin_path(name: str) -> Path:
    d = _core_dir(name)
    if name == "xray":
        return d / "xray"
    return d / "sing-box"


def is_installed(name: str) -> bool:
    return _bin_path(name).exists()


async def install(name: str) -> Path:
    """دانلود و نصب باینری هسته. خروجی: مسیر باینری."""
    if name not in ("xray", "singbox"):
        raise ValueError(f"unknown core {name}")
    if platform.system() != "Linux":
        raise RuntimeError(
            f"نصب هسته‌ی {name} فقط روی لینوکس (سرور) انجام می‌شود — "
            f"این سیستم {platform.system()} است."
        )
    arch = _arch()
    d = _core_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "dl.bin"

    if name == "xray":
        # Xray-linux-64.zip / Xray-linux-arm64-v8a.zip
        url = _gh_latest_asset(XRAY_REPO, f"Xray-linux-{arch}.zip")
        if not url:
            url = f"https://github.com/{XRAY_REPO}/releases/latest/download/Xray-linux-{arch}.zip"
        await _download(url, tmp)
        with zipfile.ZipFile(tmp) as z:
            z.extractall(d)
        binp = _bin_path(name)
        os.chmod(binp, 0o755)
        tmp.unlink(missing_ok=True)
        logger.info(f"core_manager: Xray نصب شد → {binp}")
        return binp

    # sing-box: نسخه‌ی پین‌شده — sing-box-<ver>-linux-<arch>.tar.gz
    arch_str = "amd64" if arch == "64" else ("arm64" if arch == "arm64-v8a" else arch)
    url = (f"https://github.com/{SINGBOX_REPO}/releases/download/"
           f"v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-linux-{arch_str}.tar.gz")
    await _download(url, tmp)
    import tarfile
    with tarfile.open(tmp, "r:gz") as t:
        t.extractall(d)
    # باینری داخل پوشه‌ی sing-box-<ver>/
    for cand in d.rglob("sing-box"):
        if cand.is_file():
            os.chmod(cand, 0o755)
            shutil.copy2(cand, _bin_path(name))
            break
    tmp.unlink(missing_ok=True)
    logger.info(f"core_manager: sing-box نصب شد → {_bin_path(name)}")
    return _bin_path(name)


async def ensure_installed(name: str) -> Path:
    if is_installed(name):
        return _bin_path(name)
    return await install(name)


async def get_version(name: str) -> Optional[str]:
    """نسخه‌ی هسته‌ی نصب‌شده (اگر اجرای آن ممکن باشد)."""
    if not is_installed(name) or platform.system() != "Linux":
        return None
    try:
        p = await asyncio.create_subprocess_exec(
            str(_bin_path(name)), "version",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(p.communicate(), timeout=10)
        first = (out or b"").decode("utf-8", "ignore").splitlines()
        for line in first:
            line = line.strip()
            if line:
                return line
        return None
    except Exception as exc:
        logger.warning(f"core_manager: گرفتن نسخه‌ی {name} ناموفق: {exc}")
        return None


# ── اجرا (یک پروسه برای کل هسته) ──────────────────────────────────────────────

async def start_core(name: str, config_path: Path) -> dict:
    """هسته را با فایل کانفیگ داده‌شده اجرا (یا ری‌استارت) می‌کند."""
    if platform.system() != "Linux":
        raise RuntimeError(f"اجرای هسته‌ی {name} فقط روی لینوکس ممکن است")
    binp = await ensure_installed(name)
    await stop_core(name)

    log_path = _core_dir(name) / "core.log"
    logf = open(log_path, "ab")
    cmd = [str(binp), "run", "-c", str(config_path)]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=logf, stderr=logf,
        preexec_fn=_raise_nofile,
    )
    logf.close()
    await asyncio.sleep(0.8)
    if proc.returncode is not None:
        tail = _log_tail(log_path)
        raise RuntimeError(f"هسته‌ی {name} بلافاصله متوقف شد:\n{tail}")
    _state[name] = {
        "bin": binp, "proc": proc, "config_path": config_path,
        "started_at": asyncio.get_event_loop().time(),
    }
    asyncio.create_task(_watch_core(name, proc))
    logger.info(f"core_manager: هسته‌ی {name} اجرا شد (pid={proc.pid}, config={config_path.name})")
    return {"pid": proc.pid}


def _raise_nofile():
    """RLIMIT_NOFILE را بالا می‌برد (مثل mtproto)."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(65535, hard) if hard != -1 else 65535
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


def _log_tail(log_path: Path, n: int = 800) -> str:
    try:
        return log_path.read_text(errors="ignore")[-n:]
    except Exception:
        return ""


async def _watch_core(name: str, proc):
    rc = await proc.wait()
    st = _state.get(name) or {}
    if st.get("proc") is proc:
        logger.warning(f"core_manager: هسته‌ی {name} با کد {rc} متوقف شد")


async def stop_core(name: str):
    st = _state.pop(name, None)
    if not st:
        return
    proc = st.get("proc")
    if proc and proc.returncode is None:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=6)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
    logger.info(f"core_manager: هسته‌ی {name} متوقف شد")


def is_running(name: str) -> bool:
    st = _state.get(name)
    return bool(st and st.get("proc") and st["proc"].returncode is None)


def core_status(name: str) -> dict:
    st = _state.get(name) or {}
    proc = st.get("proc")
    return {
        "installed": is_installed(name),
        "running": bool(proc and proc.returncode is None),
        "pid": proc.pid if (proc and proc.returncode is None) else None,
        "log_tail": _log_tail(_core_dir(name) / "core.log", 600),
    }


async def full_status(name: str) -> dict:
    st = core_status(name)
    st["version"] = await get_version(name)
    return st

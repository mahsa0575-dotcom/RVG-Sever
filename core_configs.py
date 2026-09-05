# core_configs.py
# ══════════════════════════════════════════════════════════════════════════════
# تولید کانفیگ JSON اینباندها برای هسته‌های Xray و sing-box از مدل لینک پنل.
# هر هسته یک پروسه با «کل» اینباندهای متعلق به خودش اجرا می‌شود (مدل 3x-ui/S-UI).
# روی هر تغییر (ساخت/ویرایش/حذف) کانفیگ دوباره نوشته و هسته ری‌استارت می‌شود.
# ══════════════════════════════════════════════════════════════════════════════

import base64
import ipaddress
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger("RVG-Gateway")

DATA_DIR = Path(__file__).resolve().parent / "data"

# پروتکل‌هایی که به هسته‌ی خارجی نیاز دارند و پورت مستقل می‌خواهند
CORE_PROTOCOLS = {
    "xray": {"vless", "vmess", "trojan", "shadowsocks", "mtproto", "socks", "http"},
    "singbox": {"vless", "vmess", "trojan", "shadowsocks", "mixed", "http", "socks",
                "hysteria", "hysteria2", "tuic"},
}

TRANSPORTS_XRAY = {"tcp", "ws", "httpupgrade", "xhttp-packet-up", "xhttp-stream-up"}
TRANSPORTS_SINGBOX = {"tcp", "ws", "httpupgrade", "grpc"}


def _c(d):  # دسترسی امن به دیکشنری
    return d if isinstance(d, dict) else {}


def _transport_of(link: dict) -> str:
    p = link.get("protocol", "")
    if p.endswith("-ws"):
        return "ws"
    if p.endswith("-httpupgrade"):
        return "httpupgrade"
    if "xhttp" in p:
        return "xhttp-packet-up"
    return "tcp"


def _base_proto(link: dict) -> str:
    p = link.get("protocol", "")
    for b in ("vless", "vmess", "trojan", "shadowsocks", "mtproto"):
        if p == b or p.startswith(b + "-"):
            return b
    return p


def _listen_port(link: dict, fallback: int = 0) -> int:
    return int(link.get("listen_port") or link.get("mtproto_port") or fallback or 0)


# ── گواهی TLS خودامضا (وقتی کاربر فایل نداده باشد) ────────────────────────────

def ensure_panel_cert(data_dir: Path | None = None, host: str = "") -> tuple[Path, Path]:
    """گواهی سراسری پنل — مثل S-UI یک‌بار در اول کار ساخته می‌شود و همه‌ی
    اینباندهای TLS/Hysteria2/TUIC از همین استفاده می‌کنند (self-signed ۱۰ ساله)."""
    cert_dir = Path(data_dir or DATA_DIR) / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    crt = cert_dir / "panel.crt"
    key = cert_dir / "panel.key"
    if crt.exists() and key.exists():
        return crt, key

    host = (host or "").strip() or "rvg.local"
    key_p = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "RVG Gateway"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "RVG"),
    ])
    san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    try:
        if host.replace(".", "").isdigit() and host.count(".") == 3:
            san.append(x509.IPAddress(ipaddress.ip_address(host)))
        else:
            san.append(x509.DNSName(host))
    except Exception:
        pass
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key_p.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key_p, hashes.SHA256())
    )
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(key_p.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    x509.load_pem_x509_certificate(crt.read_bytes())  # اعتبارسنجی
    logger.info(f"core_configs: گواهی سراسری پنل ساخته شد → {crt}")
    return crt, key


def _ensure_tls_cert(link: dict, uuid: str) -> tuple[Path, Path]:
    """مسیر گواهی/کلید TLS: فایل کاربر اگر داده باشد، وگرنه گواهی سراسری پنل."""
    user_cert, user_key = (link.get("tls_cert") or "").strip(), (link.get("tls_key") or "").strip()
    if user_cert and user_key:
        return Path(user_cert), Path(user_key)
    return ensure_panel_cert()

    sni = (link.get("sni") or "").strip() or "rvg.local"
    key_p = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, sni)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key_p.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(sni) if "." in sni else x509.DNSName("localhost"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key_p, hashes.SHA256())
    )
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(key_p.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    logger.info(f"core_configs: گواهی TLS خودامضا برای {uuid[:8]}… ساخته شد (SNI={sni})")
    return crt, key


# ══════════════════════════════════════════════════════════════════════════════
# Xray
# ══════════════════════════════════════════════════════════════════════════════

def _xray_stream(link: dict, uuid: str) -> dict:
    transport = _transport_of(link)
    sec = (link.get("security") or "").strip().lower()
    sni = (link.get("sni") or "").strip() or (link.get("reality_dest") or "").strip() or "www.cloudflare.com"
    net = {"xhttp-packet-up": "xhttp", "xhttp-stream-up": "xhttp"}.get(transport, transport)

    ss: dict = {"network": net, "security": "none"}

    if net == "ws":
        ss["wsSettings"] = {"path": f"/ws/{uuid}"}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": f"/ws/{uuid}", "host": sni}
    elif net == "xhttp":
        mode = "packet-up" if "packet" in link.get("protocol", "") else "stream-up"
        ss["xhttpSettings"] = {"path": f"/xhttp-siz10/{mode}/{uuid}", "mode": mode}

    if sec == "tls":
        crt, key = _ensure_tls_cert(link, uuid)
        ss["security"] = "tls"
        ss["tlsSettings"] = {
            "serverName": sni,
            "certificates": [{"certificateFile": str(crt), "keyFile": str(key)}],
            "alpn": [a for a in (link.get("alpn") or "h2,http/1.1").split(",") if a],
        }
    elif sec == "reality":
        ss["security"] = "reality"
        ss["realitySettings"] = {
            "show": False,
            "dest": f"{sni}:443",
            "xver": 0,
            "serverNames": [sni],
            "privateKey": link.get("reality_priv") or "",
            "shortIds": [link.get("reality_sid") or ""],
        }
    return ss


def _xray_inbound(link: dict, uuid: str) -> dict | None:
    base = _base_proto(link)
    port = _listen_port(link)
    if not port:
        return None
    sni = (link.get("sni") or "").strip() or "www.cloudflare.com"

    if base == "vless":
        flow = (link.get("flow") or "").strip()
        if (link.get("security") or "").lower() == "reality" and not flow:
            flow = "xtls-rprx-vision"
        settings = {"clients": [{"id": uuid, "flow": flow}], "decryption": "none"}
        protocol = "vless"
    elif base == "vmess":
        settings = {"clients": [{"id": uuid, "alterId": 0}]}
        protocol = "vmess"
    elif base == "trojan":
        settings = {"clients": [{"password": uuid}]}
        protocol = "trojan"
    elif base == "shadowsocks":
        settings = {
            "method": link.get("ss_cipher") or "chacha20-ietf-poly1305",
            "password": link.get("ss_password") or "",
            "network": "tcp,udp",
        }
        protocol = "shadowsocks"
    elif base == "mtproto":
        secret = link.get("mtproto_secret")
        if not secret:
            return None
        settings = {"clients": [{"secret": secret}]}
        protocol = "mtproto"
    elif base in ("socks", "http"):
        settings = {"auth": "password", "accounts": [{"user": uuid[:8], "pass": uuid}]}
        protocol = "socks" if base == "socks" else "http"
    else:
        return None

    inbound = {
        "tag": f"in-{uuid[:8]}",
        "listen": "0.0.0.0",
        "port": port,
        "protocol": protocol,
        "settings": settings,
        "sniffing": {"enabled": bool(link.get("sniffing", True)),
                     "destOverride": ["http", "tls", "quic"]},
    }
    if base not in ("shadowsocks", "mtproto", "socks", "http"):
        inbound["streamSettings"] = _xray_stream(link, uuid)
    return inbound


def build_xray_config(links: list[dict]) -> dict:
    inbounds = []
    for link in links:
        uid = link.get("uuid") or ""
        ib = _xray_inbound(link, uid)
        if ib:
            inbounds.append(ib)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# sing-box
# ══════════════════════════════════════════════════════════════════════════════

def _singbox_tls(link: dict, uuid: str, server_name: str, allow_reality: bool = True) -> dict | None:
    sec = (link.get("security") or "").strip().lower()
    if sec == "reality" and allow_reality:
        return {
            "enabled": True,
            "server_name": server_name,
            "reality": {
                "enabled": True,
                "handshake": {"server": server_name, "server_port": 443},
                "private_key": link.get("reality_priv") or "",
                "short_id": [link.get("reality_sid") or ""] if link.get("reality_sid") else [],
            },
            "utls": {"enabled": True, "fingerprint": link.get("fingerprint") or "chrome"},
        }
    if sec == "tls":
        crt, key = _ensure_tls_cert(link, uuid)
        return {
            "enabled": True,
            "server_name": server_name,
            "certificate_path": str(crt),
            "key_path": str(key),
        }
    return None


def _singbox_inbound(link: dict, uuid: str) -> dict | None:
    base = _base_proto(link)
    port = _listen_port(link)
    if not port:
        return None
    sni = (link.get("sni") or "").strip() or (link.get("reality_dest") or "").strip() or "www.cloudflare.com"
    transport = _transport_of(link)
    sec = (link.get("security") or "").strip().lower()

    tag = f"in-{uuid[:8]}"

    if base in ("vless", "vmess", "trojan"):
        ib = {"type": base, "tag": tag, "listen": "0.0.0.0", "listen_port": port}
        if base == "vless":
            flow = (link.get("flow") or "").strip()
            if sec == "reality" and not flow:
                flow = "xtls-rprx-vision"
            ib["users"] = [{"name": uuid, "uuid": uuid, "flow": flow}]
        elif base == "vmess":
            ib["users"] = [{"name": uuid, "uuid": uuid, "alterId": 0}]
        else:
            ib["users"] = [{"name": uuid, "password": uuid}]
        if transport in ("ws", "httpupgrade", "grpc"):
            ttype = {"httpupgrade": "httpupgrade", "grpc": "grpc"}.get(transport, "ws")
            tr: dict = {"type": ttype}
            if ttype == "ws":
                tr["path"] = f"/ws/{uuid}"
            elif ttype == "grpc":
                tr["service_name"] = ""
            ib["transport"] = tr
        if sec in ("tls", "reality"):
            tls = _singbox_tls(link, uuid, sni)
            if tls:
                ib["tls"] = tls
        return ib

    if base == "shadowsocks":
        return {
            "type": "shadowsocks", "tag": tag, "listen": "0.0.0.0", "listen_port": port,
            "method": link.get("ss_cipher") or "chacha20-ietf-poly1305",
            "password": link.get("ss_password") or "",
        }

    if base == "mixed":
        return {
            "type": "mixed", "tag": tag, "listen": "0.0.0.0", "listen_port": port,
            "users": [{"username": uuid[:8], "password": uuid}],
        }

    if base == "http":
        return {
            "type": "http", "tag": tag, "listen": "0.0.0.0", "listen_port": port,
            "users": [{"username": uuid[:8], "password": uuid}],
        }

    if base == "socks":
        return {
            "type": "socks", "tag": tag, "listen": "0.0.0.0", "listen_port": port,
            "users": [{"username": uuid[:8], "password": uuid}],
        }

    if base == "hysteria2":
        return {
            "type": "hysteria2", "tag": tag, "listen": "0.0.0.0", "listen_port": port,
            "users": [{"password": uuid}],
            "tls": {
                "enabled": True,
                "server_name": sni,
                "certificate_path": str(_ensure_tls_cert(link, uuid)[0]),
                "key_path": str(_ensure_tls_cert(link, uuid)[1]),
            },
        }

    if base == "hysteria":
        return {
            "type": "hysteria", "tag": tag, "listen": "0.0.0.0", "listen_port": port,
            "users": [{"auth": uuid}],
            "up_mbps": 100, "down_mbps": 100,
            "tls": {
                "enabled": True,
                "server_name": sni,
                "certificate_path": str(_ensure_tls_cert(link, uuid)[0]),
                "key_path": str(_ensure_tls_cert(link, uuid)[1]),
            },
        }

    if base == "tuic":
        return {
            "type": "tuic", "tag": tag, "listen": "0.0.0.0", "listen_port": port,
            "users": [{"uuid": uuid, "password": uuid[:12]}],
            "congestion_control": "bbr",
            "tls": {
                "enabled": True,
                "server_name": sni,
                "certificate_path": str(_ensure_tls_cert(link, uuid)[0]),
                "key_path": str(_ensure_tls_cert(link, uuid)[1]),
            },
        }

    return None


def build_singbox_config(links: list[dict]) -> dict:
    inbounds = []
    for link in links:
        uid = link.get("uuid") or ""
        ib = _singbox_inbound(link, uid)
        if ib:
            inbounds.append(ib)
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }


# ── نوشتن فایل کانفیگ ─────────────────────────────────────────────────────────

def write_core_config(name: str, links: list[dict], data_dir: Path) -> Path:
    """کانفیگ JSON هسته را می‌نویسد و مسیرش را برمی‌گرداند."""
    cfg_dir = Path(data_dir) / "cores" / ("xray" if name == "xray" else "singbox")
    cfg_dir.mkdir(parents=True, exist_ok=True)
    path = cfg_dir / "config.json"
    cfg = build_xray_config(links) if name == "xray" else build_singbox_config(links)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
    return path


def core_ports(links: list[dict], name: str) -> set[int]:
    """پورت‌هایی که این هسته مستقیماً bind می‌کند."""
    ports = set()
    for link in links:
        if (link.get("core") or "unicorn") != name:
            continue
        if not link.get("active", True):
            continue
        port = _listen_port(link)
        if port:
            ports.add(port)
    return ports

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f2027,50:203a43,100:2c5364&height=220&section=header&text=RVG%20Gateway&fontSize=60&fontColor=ffffff&animation=fadeIn&fontAlignY=38&desc=Multi-Protocol%20Proxy%20Panel%20%C2%B7%20VPS%20Edition&descAlignY=58&descSize=18" width="100%"/>

<a href="#-english"><img src="https://img.shields.io/badge/🇬🇧-English-0f2027?style=for-the-badge" /></a>
<a href="#-فارسی"><img src="https://img.shields.io/badge/🇮🇷-فارسی-203a43?style=for-the-badge" /></a>

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Async-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![VPS](https://img.shields.io/badge/Deploy-VPS%20%2F%20Dedicated%20Server-2c5364?style=for-the-badge&logo=linux&logoColor=white)](#-quick-start-vps)
[![License](https://img.shields.io/badge/License-Custom-red?style=for-the-badge)](./LICENSE)

<br/>

**v10.0 — VPS Edition** · هر کانفیگ می‌تواند پورت اختصاصی خودش را داشته باشد · بدون وابستگی به هیچ پلتفرم ابری

</div>

---

<div align="center">
<h1>🇬🇧 English</h1>
</div>

## 📖 Table of Contents

- [Overview](#-overview)
- [What changed in v10 (VPS Edition)](#-what-changed-in-v10-vps-edition)
- [Supported Protocols](#-supported-protocols)
- [Quick Start (VPS)](#-quick-start-vps)
- [Custom Ports](#-custom-ports)
- [Environment Variables](#-environment-variables)
- [TLS / Reverse Proxy](#-tls--reverse-proxy)
- [Project Structure](#-project-structure)
- [License](#-license)

<br/>

## 🚀 Overview

**RVG Gateway** is a self-hosted **multi-protocol proxy management panel** built with **Python + FastAPI**, designed to run directly on your own **VPS / dedicated server**.

It gives you a polished admin dashboard to create, monitor, and manage proxy links across multiple protocols — with per-config traffic quotas, expiry dates, custom server ports, subscription URLs, QR codes and live connection monitoring.

<br/>

## 🆕 What changed in v10 (VPS Edition)

- **No third-party platform required** — everything (Railway API integration, TCP-proxy bots, domain generators) was removed. The panel binds ports directly on your server.
- **Custom port per config** — every link can get its own listening port on the VPS (auto-assigned or user-chosen). The panel opens and manages those listeners automatically.
- **New protocol: VMess** — a full native implementation of the modern VMess AEAD handshake (`aes-128-gcm` + `chacha20-poly1305`), over WebSocket, HTTPUpgrade and raw TCP.
- **Native Shadowsocks TCP** — classic `ss://` links without any plugin, in addition to the existing v2ray-plugin (WS) mode.
- **HTTPUpgrade transport** for VLESS / VMess / Trojan.
- **Server settings inside the dashboard** — public domain/IP, TLS mode for links, port auto-assign range, live listener status.
- **Zeus SOCKS5 is now a real proxy** bound to a port you choose (limits: traffic / expiry / per-IP connections).
- **No phone-home** — the central service and self-updater are disabled by default.
- **One-command installer** with a systemd service.

<br/>

## 🌐 Supported Protocols

| Protocol | Transports | Port model |
|---|---|---|
| VLESS | WebSocket / HTTPUpgrade / XHTTP (packet-up, stream-up) | panel port or custom port |
| VMess | WebSocket / HTTPUpgrade / raw TCP (AEAD: aes-128-gcm, chacha20-poly1305) | panel port (WS) or custom port |
| Trojan | WebSocket / HTTPUpgrade / XHTTP | panel port or custom port |
| Shadowsocks | v2ray-plugin (WS) and **native TCP** (AEAD: chacha20-ietf-poly1305, aes-256-gcm) | custom port (TCP) |
| MTProto (Telegram) | official `mtproto-proxy` binary (FakeTLS + ad-tag supported) | always own TCP port |

> Multi-user, per-link quota/expiry, subscription pages and QR export work with every protocol. Mux (v1.mux.cool) and UDP-over-VMess are not supported by the native relays — disable mux in your client for VMess configs.

<br/>

## ⚡ Quick Start (VPS)

```bash
# 1) Get the code on your server
git clone <your-repo-url> /opt/rvg
cd /opt/rvg

# 2) Run the installer (installs deps, creates systemd service, prints admin password)
sudo bash install.sh --port 8000
```

Then open `http://SERVER_IP:8000/dashboard`, log in with the printed password, and go to **Settings → Server settings** to set your public domain/IP.

Manual install (any Linux):

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python main.py --port 8000
```

Docker (optional): `docker run -p 8000:8000 -v ./data:/app/data <image>` — the container must run with `--init` or as PID 1 with signal forwarding for MTProto subprocesses.

<br/>

## 🔌 Custom Ports

Every config can get its own port:

- **Create modal → "Custom port"** — leave empty for auto-assign from the configured range, or type the exact port. For protocols that ride on HTTP paths (VLESS/VMess/Trojan over WS/XHTTP) an empty port means "serve on the panel port".
- **`vmess-tcp`, `shadowsocks-tcp`, `mtproto` always get their own TCP port** (auto or chosen).
- The listener is opened/closed automatically and restored after restart. Its status is shown on each config card and in **Settings → listeners**.
- **Public port** — if the server sits behind a proxy/CDN that exposes a different external port, set it so links show the client-facing port.
- Open firewall ports: `ufw allow <port>/tcp` (the installer pre-opens `20000:40000` and MTProto's `8500:8600`).

<br/>

## ⚙️ Environment Variables

| Variable | Description | Default |
|---|---|---|
| `PORT` | Panel port (also `--port` flag) | `8000` |
| `ADMIN_PASSWORD` | Admin panel password | `123456` |
| `RVG_HOST` | Public domain/IP used in generated links (locks the settings field) | *set in dashboard* |
| `RVG_TLS` | `1` → generated links use TLS (`wss://`, `security=tls`) | off |
| `DATA_DIR` | Where state/secret/MTProto files live | `./data` |
| `CENTRAL_URL` | Optional central service for announcements/support | *disabled* |
| `UPDATE_MANIFEST_URL` | Optional self-update manifest | *disabled* |

<br/>

## 🔐 TLS / Reverse Proxy

The panel itself serves plain HTTP; two options for TLS:

1. **Reverse proxy (recommended)** — put nginx/caddy with a Let's Encrypt certificate in front, then turn on **"Links with TLS"** in Settings. Links will be generated with `security=tls` / `wss://`.
2. **Direct ports without TLS** — VLESS/VMess/Trojan links work with `security=none`; Shadowsocks-TCP and MTProto have their own encryption and never need TLS.

<br/>

## 📂 Project Structure

```
RVG/
├── protocol/
│   ├── vless/          # VLESS relay (WS + XHTTP transports)
│   ├── vmess/          # VMess AEAD implementation (codec + WS + TCP server)
│   ├── trojan/         # Trojan relay (WS + XHTTP)
│   ├── shadowsocks/    # SS AEAD (WS + native TCP server)
│   └── mtproto/        # official MTProxy binary manager
├── main.py             # FastAPI app: API, subscriptions, link/port management
├── port_manager.py     # dynamic custom-port listeners (uvicorn + raw TCP)
├── pages.py            # dashboard UI
├── zeussocks5.py       # Zeus SOCKS5 proxy (own port)
├── central.py          # optional central service (off by default)
├── updater.py          # optional self-update (off by default)
├── install.sh          # VPS installer
└── rvg-gateway.service # systemd unit
```

<br/>

## 📄 License

This project is distributed under a **custom license**:
✅ Free to use, deploy, and fork · ❌ Modifying and redistributing a modified version is **not permitted**
See the full [LICENSE](./LICENSE) file for details.

---

<div align="center" dir="rtl">
<h1>🇮🇷 فارسی</h1>
</div>

## 🚀 معرفی

**RVG Gateway** یک پنل مدیریت پروکسی چندپروتکلی خودمیزبان است که با **Python + FastAPI** ساخته شده و مستقیماً روی **سرور مجازی (VPS) یا اختصاصی** خودتان اجرا می‌شود.

داشبوردی زیبا برای ساخت، مانیتور و مدیریت لینک‌های پروکسی در پروتکل‌های مختلف — با سهمیه ترافیک و انقضای جداگانه برای هر کانفیگ، **پورت اختصاصی روی سرور**، صفحه اشتراک، خروجی QR و مانیتورینگ زنده اتصالات.

> این نسخه (v10.0) کاملاً برای VPS بازسازی شده و تمام وابستگی‌ها به پلتفرم‌های ابری حذف شده است.

<br/>

## 🆕 تغییرات نسخه v10 (نسخه VPS)

- **حذف کامل وابستگی به پلتفرم ابری** — همه‌چیز مستقیماً روی سرور شما bind می‌شود؛ دیگر به هیچ API خارجی برای ساخت پروکسی نیاز نیست.
- **پورت اختصاصی برای هر کانفیگ** — هر لینک می‌تواند پورت خودش را روی سرور داشته باشد (خودکار یا دستی). listenerها به‌صورت خودکار بالا آورده، بسته و بعد از ری‌استارت بازسازی می‌شوند.
- **پروتکل جدید VMess** — پیاده‌سازی بومیِ کامل هندشیک مدرن AEAD با رمزنگاری `aes-128-gcm` و `chacha20-poly1305`، روی WebSocket، HTTPUpgrade و TCP خام.
- **Shadowsocks بومی TCP** — لینک کلاسیک `ss://` بدون هیچ پلاگینی، علاوه بر حالت v2ray-plugin (WS).
- **ترنسپورت HTTPUpgrade** برای VLESS / VMess / Trojan.
- **تنظیمات سرور داخل پنل** — دامنه/IP عمومی، حالت TLS لینک‌ها، بازه‌ی پورت خودکار و وضعیت زنده‌ی listenerها.
- **Zeus SOCKS5 واقعی شد** — سرور SOCKS5 روی پورت دلخواه شما (با محدودیت حجم/انقضا/اتصال per-IP).
- **بدون تماس با سرور خارجی** — سرویس مرکزی و بروزرسانی خودکار به‌صورت پیش‌فرض خاموش‌اند.
- **نصب با یک دستور** + سرویس systemd.

<br/>

## 🌐 پروتکل‌های پشتیبانی‌شده

| پروتکل | ترنسپورت‌ها | مدل پورت |
|---|---|---|
| VLESS | WebSocket / HTTPUpgrade / XHTTP | پورت پنل یا پورت اختصاصی |
| VMess | WebSocket / HTTPUpgrade / TCP خام (AEAD) | پورت پنل (WS) یا پورت اختصاصی |
| Trojan | WebSocket / HTTPUpgrade / XHTTP | پورت پنل یا پورت اختصاصی |
| Shadowsocks | v2ray-plugin (WS) و **TCP بومی** | پورت اختصاصی (TCP) |
| MTProto (تلگرام) | باینری رسمی mtproto-proxy (FakeTLS + تبلیغ کانال) | همیشه پورت TCP مستقل |

> چندکاربره، سهمیه/انقضا برای هر کانفیگ، صفحه اشتراک و QR با همه‌ی پروتکل‌ها کار می‌کند. Mux و UDP-over-VMess در ریلی بومی پشتیبانی نمی‌شود — برای کانفیگ‌های VMess گزینه‌ی mux کلاینت را خاموش کنید.

<br/>

## ⚡ شروع سریع (VPS)

```bash
# ۱) کد را روی سرور بگذارید
git clone <repo-url> /opt/rvg
cd /opt/rvg

# ۲) نصب‌کننده را اجرا کنید (پیش‌نیازها + سرویس systemd + رمز تصادفی)
sudo bash install.sh --port 8000
```

بعد `http://SERVER_IP:8000/dashboard` را باز کنید، با رمز چاپ‌شده وارد شوید و از **تنظیمات → تنظیمات سرور** دامنه یا IP عمومی سرور را ثبت کنید.

نصب دستی:

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python main.py --port 8000
```

<br/>

## 🔌 پورت اختصاصی

- در مودال ساخت کانفیگ، فیلد **«پورت سرور»**: خالی = خودکار از بازه‌ی تنظیمات؛ عدد = همان پورت.
- برای پروتکل‌های مسیر-based (WS/XHTTP) خالی یعنی «روی پورت خود پنل»؛ برای `vmess-tcp`، `shadowsocks-tcp` و `mtproto` همیشه یک پورت TCP مستقل رزرو می‌شود.
- **پورت عمومی**: اگر پشت پروکسی/CDN هستید و پورت بیرونی متفاوت است، برای ساخت درست لینک‌ها آن را وارد کنید.
- وضعیت هر پورت روی کارت کانفیگ و در **تنظیمات → بازسازی پورت‌ها** دیده می‌شود.
- فایروال: `ufw allow <port>/tcp` (نصب‌کننده بازه‌ی `20000:40000` و `8500:8600` را باز می‌کند).

<br/>

## ⚙️ متغیرهای محیطی

| متغیر | توضیح | پیش‌فرض |
|---|---|---|
| `PORT` | پورت پنل (یا فلگ `--port`) | `8000` |
| `ADMIN_PASSWORD` | رمز ورود پنل | `123456` |
| `RVG_HOST` | دامنه/IP عمومی برای لینک‌ها (فیلد تنظیمات را قفل می‌کند) | *در پنل* |
| `RVG_TLS` | `1` → لینک‌ها با TLS ساخته می‌شوند | خاموش |
| `DATA_DIR` | محل ذخیره‌ی state/سکرت/فایل‌های MTProto | `./data` |
| `CENTRAL_URL` | سرویس مرکزی اختیاری (اعلان/پشتیبانی) | غیرفعال |
| `UPDATE_MANIFEST_URL` | مانیفست بروزرسانی خودکار اختیاری | غیرفعال |

<br/>

## 🔐 TLS / پروکسی معکوس

پنل خودش HTTP ساده سرو می‌کند؛ دو راه برای TLS:

1. **پروکسی معکوس (پیشنهادی)** — nginx/caddy با گواهی Let's Encrypt جلوی پنل، بعد گزینه‌ی **«لینک‌ها با TLS»** را در تنظیمات روشن کنید.
2. **پورت‌های مستقیم بدون TLS** — لینک‌های VLESS/VMess/Trojan با `security=none` کار می‌کنند؛ Shadowsocks-TCP و MTProto رمزنگاری خودشان را دارند و به TLS نیاز ندارند.

<br/>

## 📄 لایسنس

این پروژه تحت **لایسنس سفارشی** منتشر شده است:
✅ استفاده، دیپلوی و فورک آزاد · ❌ تغییر و بازنشر نسخه‌ی تغییریافته **مجاز نیست**
برای جزئیات کامل به فایل [LICENSE](./LICENSE) مراجعه کنید.

<br/>

<div align="center">

**ساخته‌شده با ❤️ توسط [codebox](https://github.com/arvin341az-glitch)**

</div>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:2c5364,50:203a43,100:0f2027&height=120&section=footer" width="100%"/>

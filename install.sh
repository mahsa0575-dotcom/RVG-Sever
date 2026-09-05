#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# RVG Gateway — نصب‌کننده‌ی VPS (نسخه v10.0)
#   اجرا:  sudo bash install.sh [--port 8000]
# کارهایی که انجام می‌دهد:
#   ۱) نصب پیش‌نیازهای سیستم (python3, venv, ابزار build برای MTProto)
#   ۲) ساخت محیط مجازی و نصب وابستگی‌های پایتون
#   ۳) ساخت سرویس systemd با رمز ادمین تصادفی
#   ۴) راه‌اندازی سرویس و چاپ اطلاعات ورود
# ══════════════════════════════════════════════════════════════════════════════
set -e

PORT=8000
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port|-p) PORT="$2"; shift 2;;
    *) echo "پارامتر ناشناخته: $1"; exit 1;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "❌ این اسکریپت باید با sudo اجرا شود"
  exit 1
fi

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="/etc/rvg-gateway.env"
SVC_FILE="/etc/systemd/system/rvg-gateway.service"

echo "▶ نصب پیش‌نیازهای سیستم..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-pip git curl \
    build-essential libssl-dev zlib1g-dev >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y python3 python3-pip git curl gcc make openssl-devel zlib-devel
elif command -v yum >/dev/null 2>&1; then
  yum install -y python3 python3-pip git curl gcc make openssl-devel zlib-devel
else
  echo "⚠ دیستریبیوشن شناخته نشد — پایتون ۳.۱۱+ را دستی نصب کنید"
fi

echo "▶ ساخت محیط مجازی پایتون..."
cd "$APP_DIR"
python3 -m venv venv
./venv/bin/pip install --upgrade pip -q
./venv/bin/pip install -r requirements.txt -q

echo "▶ ساخت فایل تنظیمات سرویس..."
ADMIN_PASSWORD_GENERATED=""
if [[ ! -f "$ENV_FILE" ]]; then
  ADMIN_PASSWORD_GENERATED=1
  ADMIN_PW=$(python3 -c "import secrets;print(secrets.token_urlsafe(12))")
  cat > "$ENV_FILE" <<EOF
# تنظیمات RVG Gateway
PORT=$PORT
ADMIN_PASSWORD=$ADMIN_PW
# RVG_HOST=vpn.example.com
# RVG_TLS=1
EOF
  chmod 600 "$ENV_FILE"
fi

echo "▶ ساخت سرویس systemd..."
cat > "$SVC_FILE" <<EOF
[Unit]
Description=RVG Gateway - Multi-Protocol Proxy Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/python main.py --port $PORT
EnvironmentFile=$ENV_FILE
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable rvg-gateway >/dev/null 2>&1
systemctl restart rvg-gateway

# باز کردن پورت پنل و بازه‌ی پورت‌های کانفیگ در فایروال (در صورت وجود ufw)
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  echo "▶ باز کردن پورت‌ها در ufw..."
  ufw allow "$PORT"/tcp >/dev/null
  ufw allow 20000:40000/tcp >/dev/null
  ufw allow 8500:8600/tcp >/dev/null
fi

sleep 2
STATUS=$(systemctl is-active rvg-gateway || true)

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  ✅ RVG Gateway نصب شد  (وضعیت سرویس: $STATUS)"
echo "  پنل:        http://SERVER_IP:$PORT/dashboard"
echo "  سرویس:      systemctl status rvg-gateway"
echo "  لاگ:        journalctl -u rvg-gateway -f"
echo "  تنظیمات:    $ENV_FILE"
if [[ $ADMIN_PASSWORD_GENERATED ]]; then
  echo "  رمز ادمین:  $(grep ADMIN_PASSWORD "$ENV_FILE" | cut -d= -f2)"
  echo "  ⚠ این رمز را جایی امن ذخیره کنید!"
fi
echo ""
echo "  گام بعدی: وارد پنل شوید و در «تنظیمات → تنظیمات سرور»"
echo "  دامنه یا IP عمومی سرور را وارد کنید تا لینک‌ها درست ساخته شوند."
echo "════════════════════════════════════════════════════════════"

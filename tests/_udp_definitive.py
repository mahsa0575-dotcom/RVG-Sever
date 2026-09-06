# -*- coding: utf-8 -*-
"""تست تعیین‌کننده UDP: شنونده روی سرور + ارسال همزمان از بیرون"""
import socket
import sys
import time
sys.path.insert(0, "tests")
from _ssh_diag import connect, run, PASS

SERVER = "46.183.16.195"


def main():
    c = connect()

    # ۱) شنونده‌های UDP روی سرور (تست روی 19999 که هیچ چیز نمی‌گیرد)
    run(c, "echo '" + PASS + "' | sudo -S bash -c 'nohup timeout 75 nc -u -l 19999 > /tmp/udp_in.txt 2>/dev/null &' ", timeout=30)
    time.sleep(1)

    # ۲) ارسال از بیرون (این ویندوز)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    for i in range(5):
        s.sendto(f"RVG-UDP-PROBE-{i}".encode(), (SERVER, 19999))
        time.sleep(0.3)
    print("5 UDP packets sent to 46.183.16.195:19999 from this PC")

    # ۳) مقایسه: همین تست از خود سرور به خودش (لوکال)
    run(c, "echo RVG-LOCAL-TEST | nc -u -w1 127.0.0.1 19999", timeout=30)

    # ۴) خواندن نتیجه بعد از چند ثانیه
    time.sleep(4)
    out, _, _ = run(c, "cat /tmp/udp_in.txt 2>/dev/null | head -5; echo '---END---'", timeout=30)
    print("=== RECEIVED ON SERVER ===")
    print(out if out.strip() else "(هیچی دریافت نشد)")

    # ۵) جمع‌بندی
    if "RVG-UDP-PROBE" in out:
        print("\n✅ UDP از بیرون به سرور می‌رسد → مشکل از شبکه‌ی کلاینت (ایران) است؛ راه‌حل: پورت 443 / پورت‌هاپینگ")
    elif "RVG-LOCAL-TEST" in out:
        print("\n⛔ UDP ورودی از بیرون بلاک است (فایروال ابری یا ISP) → Hysteria2 از این راه کار نمی‌کند؛ از TCP-based استفاده کن")
    else:
        print("\n⚠ هیچ‌کدام نرسید — nc شاید بالا نیامده؛ دوباره چک شود")

    c.close()


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""تست رفت‌وبرگشت UDP از سیستم کاربر به سرور"""
import socket

SERVER = "46.183.16.195"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
ok = False
for i in range(3):
    s.sendto(f"PING-{i}".encode(), (SERVER, 19998))
    try:
        data, _ = s.recvfrom(4096)
        print("UDP round-trip:", data.decode())
        ok = True
        break
    except socket.timeout:
        print(f"try {i+1}: no reply")
s.close()
if ok:
    print("\n✅ رفت‌وبرگشت UDP کامل است — مسیر شبکه سالم")
else:
    print("\n⛔ جواب UDP از سرور برنمی‌گردد (مسیر برگشت بلاک)")

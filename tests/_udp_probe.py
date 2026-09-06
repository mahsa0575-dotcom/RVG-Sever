# -*- coding: utf-8 -*-
"""تست UDP از بیرون: ارسال به 19999 (echo سرور) و 443 (hysteria2) + کلاینت hy2 روی 443"""
import socket
import sys
import time

SERVER = "46.183.16.195"


def udp_probe(port, payload, wait=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(wait)
    try:
        s.sendto(payload, (SERVER, port))
        try:
            data, addr = s.recvfrom(4096)
            return f"RECEIVED {len(data)}B from {addr}"
        except socket.timeout:
            return "NO RESPONSE (filtered or silent)"
    except ConnectionResetError:
        return "ICMP PORT UNREACHABLE (port closed)"
    except Exception as e:
        return f"ERR: {e}"
    finally:
        s.close()


# ۱) خروجی UDP کلی (DNS)
print("DNS via UDP 8.8.8.8:", udp_probe(53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01").replace("RECEIVED", "RESPONSE"))

# ۲) به nc سرور (پورت 19999)
print("UDP to server:19999:", udp_probe(19999, b"RVG-UDP-TEST-123"))

# ۳) به hysteria2 (443) — بسته‌ی QUIC Initial شبیه‌سازی‌شده
print("UDP to server:443 (hy2):", udp_probe(443, b"\x00" + bytes([0]) + b"\x00" * 20 + b"\x00" * 1200))

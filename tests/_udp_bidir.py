# -*- coding: utf-8 -*-
"""تست رفت‌وبرگشت UDP + تست مجدد hy2 با هسته‌ی پایدار"""
import socket
import subprocess
import sys
import threading
import time
sys.path.insert(0, "tests")
from _ssh_diag import connect, run, PASS

SERVER = "46.183.16.195"


def main():
    c = connect()

    # ۱) echo server UDP روی سرور (پورت 19998)
    run(c, "echo '" + PASS + "' | sudo -S bash -c 'pkill -f udp_echo 2>/dev/null; nohup python3 -c \"\nimport socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.bind((\\\"0.0.0.0\\\", 19998))\nwhile True:\n    data, addr = s.recvfrom(4096)\n    s.sendto(b\\\"ECHO:\\\" + data, addr)\n\" > /dev/null 2>&1 &' ", timeout=30)
    time.sleep(1.5)

    # ۲) رفت‌وبرگشت از بیرون
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

    if not ok:
        print("⛔ مسیر برگشت UDP قطع است — این دلیل شکست hy2 از بیرون است")
        c.close()
        return

    # ۳) تست مجدد hy2 از این ماشین (sing-box الان 1.11.15 پایدار است)
    print("\n--- تست مجدد کلاینت Hysteria2 ---")
    cfg = r'''{
  "log": { "level": "info" },
  "inbounds": [ { "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 10809 } ],
  "outbounds": [
    { "type": "hysteria2", "tag": "hy2", "server": "46.183.16.195", "server_port": 443,
      "password": "81222a1f-2fb8-5a4a-3d9f-c7963a7b6c95",
      "tls": { "enabled": true, "server_name": "46.183.16.195", "insecure": true } },
    { "type": "direct", "tag": "direct" }
  ],
  "route": { "final": "hy2" }
}'''
    open(r"C:\Users\Markazi__BND\AppData\Local\Temp\sbclient\hy2_443.json", "w").write(cfg)
    proc = subprocess.Popen(
        [r"C:\Users\Markazi__BND\AppData\Local\Temp\sbclient\sing-box-1.11.15-windows-amd64\sing-box.exe",
         "run", "-c", r"C:\Users\Markazi__BND\AppData\Local\Temp\sbclient\hy2_443.json"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(5)
    try:
        import httpx
        r = httpx.get("http://api.ipify.org", proxy="socks5://127.0.0.1:10809", timeout=25)
        print("✅ HYSTERIA2 TUNNEL WORKS — exit IP:", r.text)
    except Exception as e:
        print("hy2 test fail:", e)
    proc.terminate()

    c.close()


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""تست تعیین‌کننده: tcpdump روی سرور + کلاینت واقعی از سیستم کاربر"""
import subprocess
import sys
import time
sys.path.insert(0, "tests")
from _ssh_diag import connect, run, PASS

SB = r"C:\Users\Markazi__BND\AppData\Local\Temp\sbclient\sing-box-1.11.15-windows-amd64\sing-box.exe"
CFG = r"C:\Users\Markazi__BND\AppData\Local\Temp\sbclient\hy2_443.json"


def main():
    c = connect()

    # ۱) نصب tcpdump و شروع ضبط (پشت‌زمینه، 45 ثانیه)
    out, _, _ = run(c, "echo '" + PASS + "' | sudo -S bash -c 'which tcpdump >/dev/null 2>&1 || apt-get install -y -qq tcpdump >/dev/null 2>&1; nohup timeout 45 tcpdump -i any -n -U udp port 443 > /tmp/hy2_cap.txt 2>&1 &' ; sleep 1; echo capture-started", timeout=120)
    print("capture:", out[:120])

    # ۲) کلاینت hy2 واقعی از سیستم کاربر (پورت 10809)
    proc = subprocess.Popen([SB, "run", "-c", CFG],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(8)
    try:
        import httpx
        try:
            r = httpx.get("http://api.ipify.org", proxy="socks5://127.0.0.1:10809", timeout=15)
            print("CLIENT RESULT: OK — exit IP:", r.text)
        except Exception as e:
            print("CLIENT RESULT: FAIL —", str(e)[:100])
    finally:
        proc.terminate()
        out, _ = proc.communicate(timeout=8)
        print("--- CLIENT LOG ---")
        print((out or b"").decode("utf-8", "ignore")[-600:])

    # ۳) خواندن ضبط سرور
    time.sleep(2)
    out, _, _ = run(c, "echo '" + PASS + "' | sudo -S bash -c 'wc -l /tmp/hy2_cap.txt; head -6 /tmp/hy2_cap.txt; echo ...; grep -c \"46.183.16.195.20005\" /tmp/hy2_cap.txt 2>/dev/null; tail -8 /tmp/hy2_cap.txt'", timeout=60)
    print("\n=== SERVER CAPTURE (UDP 443) ===")
    print(out[:1800])

    c.close()


if __name__ == "__main__":
    main()

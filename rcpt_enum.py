#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 kikspace
"""
RCPT TO user enumeration tool (SMTP pentesting methodology).
 
Проверяет список имён через RCPT TO на одном SMTP-хосте, используя одну
MAIL FROM транзакцию, и сохраняет подтверждённые (2xx) адреса в файл.
 
Использование:
    python3 rcpt_enum.py -ip <IP> -p <port> -d <domain> -w <wordlist> -o <outfile>
 
Author:   kikspace
Version:  1.0.0
License:  MIT
 
Disclaimer:
    Инструмент предназначен исключительно для авторизованного тестирования
    на проникновение в рамках согласованного скоупа (ROE/SOW). Использование
    против систем без явного разрешения является незаконным.
"""
 
__author__ = "kikspace"
__version__ = "1.0.0"
__license__ = "MIT"

import argparse
import socket
import sys
import time


def read_line(sock, timeout=10):
    sock.settimeout(timeout)
    data = b""
    while not data.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace").rstrip("\r\n")


def read_multiline(sock, timeout=10):
    """Читает многострочный ответ (250-...  250 ...) до финальной строки без дефиса."""
    lines = []
    while True:
        line = read_line(sock, timeout)
        lines.append(line)
        if len(line) >= 4 and line[3] == " ":
            break
        if not line:
            break
    return lines


def send_cmd(sock, cmd):
    sock.sendall((cmd + "\r\n").encode())


def main():
    ap = argparse.ArgumentParser(description="SMTP RCPT TO user enumeration")
    ap.add_argument("-ip", required=True, help="IP адрес целевого SMTP-сервера")
    ap.add_argument("-p", "--port", type=int, default=25, help="порт (по умолчанию 25)")
    ap.add_argument("-d", "--domain", required=True, help="домен получателя (user@domain)")
    ap.add_argument("-w", "--wordlist", required=True, help="файл со списком имён (по одному на строку)")
    ap.add_argument("-o", "--outfile", required=True, help="файл для сохранения подтверждённых адресов")
    ap.add_argument("--helo", default="mail.test.local", help="FQDN для EHLO/HELO (по умолчанию mail.test.local)")
    ap.add_argument("--mailfrom", default="test@test.local", help="адрес отправителя для MAIL FROM")
    ap.add_argument("--delay", type=float, default=0.5, help="задержка между RCPT TO в секундах (по умолчанию 0.5)")
    ap.add_argument("--timeout", type=float, default=10, help="таймаут чтения сокета в секундах (по умолчанию 10)")
    args = ap.parse_args()

    try:
        with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
            users = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[!] Не удалось открыть wordlist: {e}")
        sys.exit(1)

    print(f"[*] Загружено {len(users)} имён из {args.wordlist}")

    sock = socket.create_connection((args.ip, args.port), timeout=args.timeout)
    banner = read_line(sock, args.timeout)
    print(f"< {banner}")

    send_cmd(sock, f"EHLO {args.helo}")
    for line in read_multiline(sock, args.timeout):
        print(f"< {line}")

    send_cmd(sock, f"MAIL FROM:<{args.mailfrom}>")
    mf_resp = read_line(sock, args.timeout)
    print(f"< {mf_resp}")
    if not mf_resp.startswith("25"):
        print("[!] MAIL FROM отклонён, дальнейший перебор бессмысленен")
        sock.close()
        sys.exit(1)

    found = []
    with open(args.outfile, "a", encoding="utf-8") as out:
        for i, user in enumerate(users, 1):
            addr = f"{user}@{args.domain}"
            try:
                send_cmd(sock, f"RCPT TO:<{addr}>")
                resp = read_line(sock, args.timeout)
            except (socket.timeout, OSError) as e:
                print(f"[!] {user}: соединение оборвалось ({e}), переподключаюсь...")
                sock.close()
                sock = socket.create_connection((args.ip, args.port), timeout=args.timeout)
                read_line(sock, args.timeout)
                send_cmd(sock, f"EHLO {args.helo}")
                read_multiline(sock, args.timeout)
                send_cmd(sock, f"MAIL FROM:<{args.mailfrom}>")
                read_line(sock, args.timeout)
                send_cmd(sock, f"RCPT TO:<{addr}>")
                resp = read_line(sock, args.timeout)

            status = "VALID" if resp.startswith(("250", "251", "252")) else (
                "GREYLIST" if resp.startswith(("450", "451", "452")) else "invalid")
            print(f"[{i}/{len(users)}] {addr} -> {resp}  [{status}]")

            if status == "VALID":
                out.write(addr + "\n")
                out.flush()
                found.append(addr)
            elif status == "GREYLIST":
                print(f"    (!) greylisting — результат по {addr} неокончательный, повторить позже")

            if args.delay:
                time.sleep(args.delay)

    send_cmd(sock, "QUIT")
    sock.close()

    print(f"\n[+] Готово. Подтверждено валидных адресов: {len(found)} -> {args.outfile}")


if __name__ == "__main__":
    main()

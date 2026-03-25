#!/usr/bin/env python3
import re
from urllib.request import urlopen

BASE_URL = "http://10.0.118.48:7777/static/style.css"


def get_text(url: str) -> str:
    with urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8", errors="replace")


def main() -> None:
    css = get_text(BASE_URL)
    match = re.search(r"/\*\s*(.*?)\s*\*/", css, flags=re.DOTALL)
    if not match:
        raise RuntimeError("No CSS comment found")

    hidden = match.group(1).strip()
    print("[+] source:", BASE_URL)
    print("[+] hidden comment:", hidden)


if __name__ == "__main__":
    main()

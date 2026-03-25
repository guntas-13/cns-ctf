#!/usr/bin/env python3
from urllib.parse import urljoin
from urllib.request import urlopen

BASE_URL = "http://10.0.118.48:9999/"


def get_text(url: str) -> str:
    with urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8", errors="replace")


def extract_disallow_path(robots_txt: str) -> str | None:
    for line in robots_txt.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                path = parts[1].strip()
                if path:
                    return path
    return None


def main() -> None:
    robots_url = urljoin(BASE_URL, "robots.txt")
    robots_txt = get_text(robots_url)

    hidden_path = extract_disallow_path(robots_txt)
    if not hidden_path:
        raise RuntimeError("No Disallow path found in robots.txt")

    hidden_url = urljoin(BASE_URL, hidden_path.lstrip("/"))
    secret = get_text(hidden_url).strip()

    print("[+] robots.txt path:", hidden_path)
    print("[+] hidden URL:", hidden_url)
    print("[+] response:", secret)


if __name__ == "__main__":
    main()

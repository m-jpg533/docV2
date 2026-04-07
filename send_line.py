import requests

def send_line(msg):
    if not LINE_TOKEN or not LINE_USER_ID:
        return

    url = "https://api.line.me/v2/bot/message/push"
    headers = {
        "Authorization": f"Bearer {LINE_TOKEN}",
        "Content-Type": "application/json"
    }

    data = {
        "to": LINE_USER_ID,
        "messages":[{"type":"text","text":msg}]
    }

    requests.post(url, headers=headers, json=data)

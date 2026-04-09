from flask import Flask, request, jsonify, render_template
import sqlite3
from datetime import datetime
from urllib.parse import unquote
import requests
import os


app = Flask(__name__)
DB = "database.db"

# ===== LINE（可選）=====
LINE_TOKEN = os.getenv("LINE_TOKEN")
LINE_USER_ID = os.getenv("USER_ID")
@app.route("/test_line")
def test_line():
    send_line("SOC 測試成功🔥")
    return "ok"
def send_line(msg):
    if not LINE_TOKEN:
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

# ===== 初始化 DB =====
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        country TEXT,
        type TEXT,
        level TEXT,
        path TEXT,
        time TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ===== IP → 國家 =====



# 🌍 IP 查位置
def get_ip_info(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        return {
            "country": res.get("country", "Unknown"),
            "city": res.get("city", "Unknown"),
            "lat": res.get("lat", 0),
            "lon": res.get("lon", 0)
        }
    except:
        return {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}

# 🌐 DNS 解析
def get_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

# 🚨 LINE 通知
def send_line(msg):
    try:
        requests.post(
            "https://notify-api.line.me/api/notify",
            headers={"Authorization": f"Bearer {LINE_TOKEN}"},
            data={"message": msg},
            timeout=3
        )
    except:
        pass

# 🔍 攻擊偵測
def detect_attack(q):
    q = q.lower()
    if "<script>" in q:
        return "XSS"
    if "union" in q or "' or 1=1" in q:
        return "SQL Injection"
    return None

@app.route("/")
def home():
    q = request.args.get("q", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    attack_type = detect_attack(q)

    if attack_type:
        info = get_ip_info(ip)
        dns = get_dns(ip)

        data = {
            "time": str(datetime.datetime.now()),
            "ip": ip,
            "dns": dns,
            "type": attack_type,
            "country": info["country"],
            "city": info["city"],
            "lat": info["lat"],
            "lon": info["lon"]
        }

        attacks.append(data)

        print(f"🚨 {attack_type}: {ip}")

        # 🔥 LINE 推播
        msg = f"""
🚨 SOC 警報
類型: {attack_type}
IP: {ip}
DNS: {dns}
國家: {info['country']} {info['city']}
時間: {data['time']}
"""
        send_line(msg)

    return render_template("index.html")

@app.route("/api/attacks")
def api():
    return jsonify(attacks)

# ❤️ 健康檢查（Render不卡）
@app.route("/health")
def health():
    return "OK", 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
if __name__ == "__main__":
    app.run()

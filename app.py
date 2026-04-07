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

def send_line(msg):
    if not LINE_TOKEN:
        return
    url = "https://api.line.me/v2/bot/message/push"
    headers = {
        "Authorization": f"Bearer {LINE_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "to": "你的UserID",
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
def get_country(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        return res.get("country", "Unknown")
    except:
        return "Unknown"

# ===== 攻擊判斷 =====
def detect_attack(path, args):
    text = unquote(str(path) + str(args)).lower()

    if "<script" in text or "alert(" in text:
        return "XSS", "HIGH"
    if "login" in text or "admin" in text:
        return "SCAN", "MEDIUM"

    return "NORMAL", "LOW"

# ===== SOC 核心 =====
@app.before_request
def soc():
    ua = request.headers.get("User-Agent", "").lower()

    if "facebookexternalhit" in ua or "line" in ua:
        return

    path = request.path
    args = request.query_string.decode()

    attack_type, level = detect_attack(path, args)

    if attack_type != "NORMAL":
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)

        country = get_country(ip)

        print(f"🚨 {attack_type} {level} {ip} {country}")

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("""
        INSERT INTO attacks (ip, country, type, level, path, time)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, country, attack_type, level, path, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()

        send_line(f"🚨{attack_type}\nIP:{ip}\n國家:{country}\n等級:{level}")

# ===== API =====
@app.route("/attacks")
def attacks():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT ip,country,type,level,path,time FROM attacks ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return jsonify(rows)

# ===== Dashboard =====
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# ===== 首頁 =====
@app.route("/")
def home():
    return "SOC v2 Running 😎"

if __name__ == "__main__":
    app.run()

from flask import Flask, request, jsonify, render_template
import sqlite3
from datetime import datetime
from urllib.parse import unquote
import requests
import os

app = Flask(__name__)

# ✅ Render 可寫路徑
DB = "/tmp/database.db"

# ===== LINE =====
LINE_TOKEN = os.getenv("LINE_TOKEN")
LINE_USER_ID = os.getenv("USER_ID")

def send_line(msg):
    if not LINE_TOKEN or not LINE_USER_ID:
        print("⚠️ LINE 未設定")
        return

    url = "https://api.line.me/v2/bot/message/push"
    headers = {
        "Authorization": f"Bearer {LINE_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "to": LINE_USER_ID,
        "messages": [{"type": "text", "text": msg}]
    }

    try:
        res = requests.post(url, headers=headers, json=data)
        print("📩 LINE 發送:", res.status_code)
    except Exception as e:
        print("❌ LINE 錯誤:", e)

# 測試 LINE
@app.route("/test_line")
def test_line():
    send_line("SOC 測試成功🔥")
    return "ok"


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
        # 主 API
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2).json()
        country = res.get("country_name")
        if country:
            return country

        # 備用 API
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2).json()
        return res.get("country", "Unknown")

    except:
        return "Unknown"


# ===== 攻擊判斷 =====
def detect_attack(path, args):
    text = unquote(str(path) + str(args)).lower()

    if "<script" in text or "alert(" in text or "%3cscript" in text:
        return "XSS", "HIGH"

    if "login" in text or "admin" in text:
        return "SCAN", "MEDIUM"

    return "NORMAL", "LOW"


# ===== SOC 核心 =====
@app.before_request
def soc():
    ua = request.headers.get("User-Agent", "").lower()

    # 忽略 LINE / FB 預覽
    if "facebookexternalhit" in ua or "line" in ua:
        return

    path = request.path
    args = request.query_string.decode()

    attack_type, level = detect_attack(path, args)

    if attack_type != "NORMAL":

        # ✅ 取得真實 IP
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()

        country = get_country(ip)

        print(f"🚨 {attack_type} {level} {ip} {country}")

        # ===== 寫入 DB（含錯誤顯示）=====
        try:
            conn = sqlite3.connect(DB)
            c = conn.cursor()

            c.execute("""
            INSERT INTO attacks (ip, country, type, level, path, time)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                ip,
                country,
                attack_type,
                level,
                path,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

            conn.commit()
            conn.close()

            print("✅ DB 寫入成功")

        except Exception as e:
            print("❌ DB 錯誤:", e)

        # ===== LINE 通知 =====
        send_line(f"🚨 SOC 警報\n類型:{attack_type}\nIP:{ip}\n國家:{country}\n等級:{level}")


# ===== API =====
@app.route("/attacks")
def attacks():
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("""
        SELECT ip, country, type, level, path, time
        FROM attacks
        ORDER BY id DESC
        LIMIT 50
        """)
        rows = c.fetchall()
        conn.close()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)})


# ===== Dashboard =====
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# ===== 首頁 =====
@app.route("/")
def home():
    return "SOC v2 Running 😎"


# ===== 啟動 =====
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

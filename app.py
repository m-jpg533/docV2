from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)

# 🔥 SOC 攻擊紀錄
attack_logs = []

# 🔥 IP → 經緯度
def get_ip_location(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = r.json()

        lat = data.get("lat")
        lon = data.get("lon")

        # 🔥 重點：如果抓不到 → 給預設位置
        if lat is None or lon is None:
            return 25.03, 121.56  # 台灣

        return lat, lon

    except:
        return 25.03, 121.56  # fallback

# 🔥 首頁（地圖）
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

# 🔥 SOC API（給地圖用）
@app.route("/api/attacks")
def api_attacks():
    return jsonify(attack_logs)

# 🔥 模擬 / 真實攻擊入口（你原本應該有類似）
@app.route("/log", methods=["POST"])
def log_attack():
    ip = request.remote_addr

    # 👉 測試用（可改成你原本判斷 XSS / SQLi）
    attack_type = request.json.get("type", "UNKNOWN")

    lat, lon = get_ip_location(ip)

    attack_logs.append({
        "ip": ip,
        "type": attack_type,
        "lat": lat,
        "lon": lon
    })

    return jsonify({"status": "ok"})

# 🔥 測試用（快速產生攻擊）
@app.route("/test")
def test():
    fake_ips = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    for ip in fake_ips:
        lat, lon = get_ip_location(ip)
        attack_logs.append({
            "ip": ip,
            "type": "TEST",
            "lat": lat,
            "lon": lon
        })

    return "測試資料已加入"
@app.before_request
def detect_attack():
    q = request.args.get("q", "")

    # 🔥 偵測 XSS
    if "<script>" in q.lower():
        ip = request.remote_addr

        lat, lon = get_ip_location(ip)

        attack_logs.append({
            "ip": ip,
            "type": "XSS",
            "lat": lat,
            "lon": lon
        })

        print("🚨 偵測到 XSS 攻擊:", ip)
if __name__ == "__main__":
    app.run(debug=True)

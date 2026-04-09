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
        return data.get("lat"), data.get("lon")
    except:
        return None, None

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

if __name__ == "__main__":
    app.run(debug=True)

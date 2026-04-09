from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)

attack_logs = []

# 🔥 IP 定位
def get_ip_location(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = r.json()

        lat = data.get("lat")
        lon = data.get("lon")

        if lat is None or lon is None:
            return 25.03, 121.56  # fallback

        return lat, lon
    except:
        return 25.03, 121.56

# 🔥 偵測攻擊
@app.before_request
def detect_attack():
    q = request.args.get("q", "")

    if "<script>" in q.lower():
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)

        if ip and "," in ip:
            ip = ip.split(",")[0]

        lat, lon = get_ip_location(ip)

        attack_logs.append({
            "ip": ip,
            "type": "XSS",
            "lat": lat,
            "lon": lon
        })

        print("🚨 XSS 攻擊:", ip)

# 🔥 API
@app.route("/api/attacks")
def api_attacks():
    return jsonify(attack_logs)

# 🔥 Dashboard
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run()

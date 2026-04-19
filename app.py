from scapy.all import sniff
from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO
from collections import defaultdict
import threading
import numpy as np

app = Flask(__name__)
app.secret_key = "secret123"
socketio = SocketIO(app, cors_allowed_origins="*")

USER = {
    "username": "admin",
    "password": "1234"
}

protocol_count = defaultdict(int)
packet_sizes = []
ip_count = defaultdict(int)

def get_proto_name(proto):
    return {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP"
    }.get(proto, str(proto))

def detect_ai(pkt):
    packet_sizes.append(pkt["length"])

    if len(packet_sizes) > 20:
        mean = np.mean(packet_sizes)
        std = np.std(packet_sizes)

        if pkt["length"] > mean + 2 * std:
            return "AI ALERT 🚨"

    return ""

def detect_intrusion(pkt):
    alerts = []

    if pkt["length"] > 1500:
        alerts.append("Large Packet")

    if ip_count[pkt["src"]] > 50:
        alerts.append("Possible DDoS")

    return alerts

def process_packet(packet):
    if packet.haslayer('IP'):
        proto_num = packet['IP'].proto
        proto_name = get_proto_name(proto_num)

        pkt = {
            "src": packet['IP'].src,
            "dst": packet['IP'].dst,
            "protocol": proto_name,
            "length": len(packet)
        }

        protocol_count[proto_name] += 1
        ip_count[pkt["src"]] += 1

        pkt["alerts"] = detect_intrusion(pkt)
        pkt["ai"] = detect_ai(pkt)

        socketio.emit("packet", pkt)
        socketio.emit("stats", dict(protocol_count))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == USER["username"] and password == USER["password"]:
            session['user'] = username
            return redirect('/')
        else:
            return "Invalid Credentials ❌"

    return render_template("login.html")

@app.route('/')
def index():
    if 'user' not in session:
        return redirect('/login')
    return render_template("index.html")

# 🚪 Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

# 🚀 Sniffing
def start_sniffing():
    sniff(iface="eth0", prn=process_packet, store=False)

# ▶️ Run
if __name__ == "__main__":
    print("🚀 Starting Packet Sniffer...") 
    print("Server Running Successfully http://localhost:5001/")
    t = threading.Thread(target=start_sniffing)
    t.daemon = True
    t.start()

    socketio.run(app, host="0.0.0.0", port=5001)

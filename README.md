# Net-Analyze

# 🕵️ Network Traffic Analyzer (Python + Scapy)

A real-time network traffic analyzer built using Python, designed to capture live packets, display essential packet info in the terminal, and visualize traffic patterns graphically. Perfect for security researchers and networking students using Kali Linux.

---

## ⚙️ Features

- 📡 **Live Packet Sniffing** using Scapy
- 🎨 **Terminal Display** using Rich tables (protocol, source IP, destination IP, packet length)
- 📈 **Live Graph** of packets per second using Matplotlib
- 💾 **Automatic Packet Logging** to `.pcap` on exit
- 🧵 **Threaded sniffing** to allow simultaneous plotting and capturing

---

## 📁 Project Structure

net-analyze/
├── analyze.py # Main script
└── captured_traffic.pcap # (auto-created on exit)


---

## 📦 Requirements

Install dependencies using pip:

```bash
pip install scapy matplotlib rich

```
If using a virtual environment (✅ Recommended):
```
python3 -m venv venv
source venv/bin/activate
pip install scapy matplotlib rich


```

▶️ How to Run

Navigate to your project folder:
```
cd ~/Desktop/net-analyze
source venv/bin/activate
sudo python3 analyze.py
```
Note: Scapy needs sudo privileges to access low-level network packets.

1. 📊 Terminal Output

Real-time packet logs in a rich table:
```
┏━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Protocol ┃ Source IP    ┃ Destination IP  ┃ Length ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ TCP      │ 192.168.1.5  │ 142.250.183.206 │   1500 │
└──────────┴──────────────┴─────────────────┴────────┘
```
2. 📈 Live Graph

    A real-time Matplotlib chart showing packets per second

    Updates live while sniffing

💾 .pcap Saving on Exit
When you press CTRL+C, the analyzer:
Stops sniffing
Saves all captured packets to:
```
captured_traffic.pcap

wireshark captured_traffic.pcap
```
🧪 How to Generate Traffic

While the analyzer is running, open another terminal and try:
```
ping google.com
curl https://example.com
```
These will generate ICMP and HTTP packets captured live.


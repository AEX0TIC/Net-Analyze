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
```If using a virtual environment (✅ Recommended):
python3 -m venv venv
source venv/bin/activate
pip install scapy matplotlib rich


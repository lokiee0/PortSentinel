# PortSentinel -  Lightweight Port Scan Detector


`PortSentinel` is a simple, lightweight Intrusion Detection System built using **Scapy**. It monitors incoming TCP traffic to detect potential **port scanning attacks** on your network.

## ⚙️ Features

- Detects TCP port scans based on connection frequency
- Customizable thresholds via command-line
- Logs alerts to `alerts.log`
- Colored terminal output using `colorama`
- Graceful shutdown with Ctrl+C

## 📸 Screenshot

![screenshot](https://dummyimage.com/800x150/222/fff&text=IDS+Lite+Running...) <!-- (Optional) Replace with actual screenshot -->

---

## 🚀 Getting Started

### 🧩 Requirements

- Python 3.7+
- [Npcap](https://nmap.org/npcap/) (Windows only)
- Admin/root privileges for sniffing

### 🔧 Installation

1. **Clone the repo**  
   ```bash
   git clone https://github.com/yourusername/PortSentinel.git
   cd PortSentinel

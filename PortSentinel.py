from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime, timedelta
from colorama import init, Fore
import argparse
import signal
import sys

init(autoreset=True)

parser = argparse.ArgumentParser(description="Lightweight IDS to detect port scanning.")
parser.add_argument("--threshold", type=int, default=20)
parser.add_argument("--timewindow", type=int, default=10)
args = parser.parse_args()

PORT_SCAN_THRESHOLD = args.threshold
TIME_WINDOW = args.timewindow

connection_tracker = defaultdict(list)
last_alert_time = defaultdict(lambda: datetime.min)

def log_alert(ip, count):
    with open("alerts.log", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] ALERT: Port scan detected from {ip} (unique ports: {count})\n")

def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        dport = packet[TCP].dport
        now = datetime.now()
        connection_tracker[ip_src].append((dport, now))
        connection_tracker[ip_src] = [
            (port, t) for port, t in connection_tracker[ip_src]
            if now - t < timedelta(seconds=TIME_WINDOW)
        ]
        unique_ports = set(port for port, _ in connection_tracker[ip_src])
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            if now - last_alert_time[ip_src] > timedelta(minutes=1):
                print(Fore.RED + f"[⚠️ ALERT] Port scan detected from {ip_src} (ports: {len(unique_ports)})")
                log_alert(ip_src, len(unique_ports))
                last_alert_time[ip_src] = now
                connection_tracker[ip_src] = []

def handle_exit(sig, frame):
    print(Fore.YELLOW + "\n🛑 IDS Lite stopped by user.")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

print(Fore.GREEN + f"🔍 IDS Lite is running (Threshold: {PORT_SCAN_THRESHOLD} ports in {TIME_WINDOW}s)")
print(Fore.GREEN + "Press Ctrl+C to stop...\n")

sniff(filter="tcp", prn=detect_port_scan, store=0)

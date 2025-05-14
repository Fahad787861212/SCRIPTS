import os
import signal
import subprocess
import json
import time
import logging
from collections import defaultdict
from netfilterqueue import NetfilterQueue
from scapy.all import IP, ICMP, UDP, TCP, Raw, Ether, send, hexdump
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

FIREWALL_RULES_FILE = "firewall_rules.json"
TRAFFIC_LOG = defaultdict(list)
ALERT_LOG_FILE = "alert_log.txt"

logging.basicConfig(filename="activity_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

latest_config = {}

DISPLAY_LEVEL = 2  # Default level, can be overridden by config


def load_firewall_rules():
    rules = [
        "iptables -A INPUT -j NFQUEUE --queue-num 1",
        "iptables -A OUTPUT -j NFQUEUE --queue-num 1",
    ]
    for rule in rules:
        subprocess.run(rule, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[*] Firewall rules loaded successfully.")


def flush_iptables():
    subprocess.run("iptables -F", shell=True)
    subprocess.run("iptables -X", shell=True)
    print("[*] Flushing iptables rules...")


def load_config():
    global latest_config, DISPLAY_LEVEL
    try:
        with open(FIREWALL_RULES_FILE) as f:
            latest_config = json.load(f)
            DISPLAY_LEVEL = latest_config.get("DisplayLevel", 2)
    except Exception as e:
        print(f"[!] Failed to load config: {e}")
        latest_config = {}
    return latest_config


def log_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(ALERT_LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def packet_info(packet):
    try:
        eth = Ether(packet.original)
        ip = packet[IP]
        proto = "OTHER"
        if ip.proto == 1:
            proto = "ICMP"
        elif ip.proto == 6:
            proto = "TCP"
        elif ip.proto == 17:
            proto = "UDP"

        src_port = dst_port = "N/A"
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if DISPLAY_LEVEL == 0:
            return
        elif DISPLAY_LEVEL == 1:
            print(f"{ip.src}:{src_port} -> {ip.dst}:{dst_port} [{proto}]")
        elif DISPLAY_LEVEL == 2:
            info = (
                f"Packet Info:\n"
                f"Source MAC: {eth.src}\n"
                f"Destination MAC: {eth.dst}\n"
                f"Source IP: {ip.src}\n"
                f"Destination IP: {ip.dst}\n"
                f"Protocol: {proto}\n"
                f"Source Port: {src_port}\n"
                f"Destination Port: {dst_port}\n"
                f"Size: {len(packet)} bytes\n"
            )
            print(info)
            logging.info(info)
        elif DISPLAY_LEVEL >= 3:
            info = (
                f"Packet Info:\n"
                f"Source MAC: {eth.src}\n"
                f"Destination MAC: {eth.dst}\n"
                f"Source IP: {ip.src}\n"
                f"Destination IP: {ip.dst}\n"
                f"Protocol: {proto}\n"
                f"Source Port: {src_port}\n"
                f"Destination Port: {dst_port}\n"
                f"Size: {len(packet)} bytes\n"
                f"Payload:\n"
            )
            print(info)
            hexdump(packet)
            logging.info(info)
    except Exception as e:
        logging.error(f"Error getting packet info: {e}")


def log_traffic(ip, proto):
    now = time.time()
    TRAFFIC_LOG[(ip, proto)].append(now)
    TRAFFIC_LOG[(ip, proto)] = [t for t in TRAFFIC_LOG[(ip, proto)] if now - t <= 10]


def exceeds_threshold(ip, proto, count):
    return len(TRAFFIC_LOG[(ip, proto)]) > count


def is_malicious(packet, config):
    ip = packet[IP].src
    proto = packet[IP].proto
    payload = bytes(packet[IP].payload)

    if ip in config.get("WhitelistedIPs", []):
        return False

    if ip in config.get("ListOfBannedIpAddr", []):
        return True

    for prefix in config.get("ListOfBannedPrefixes", []):
        if ip.startswith(prefix):
            return True

    if packet.haslayer(TCP) and packet[TCP].dport in config.get("ListOfBannedPorts", []):
        return True

    if config.get("BlockPingAttacks") and packet.haslayer(ICMP):
        log_traffic(ip, "ICMP")
        if exceeds_threshold(ip, "ICMP", config["Thresholds"]["Ping"]["Count"]):
            return True

    if config.get("BlockSynFlood") and packet.haslayer(TCP) and packet[TCP].flags == "S":
        log_traffic(ip, "SYN")
        if exceeds_threshold(ip, "SYN", config["Thresholds"]["Syn"]["Count"]):
            return True

    if config.get("BlockUdpFlood") and packet.haslayer(UDP):
        log_traffic(ip, "UDP")
        if exceeds_threshold(ip, "UDP", config["Thresholds"]["Udp"]["Count"]):
            return True

    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors="ignore").lower()
        for keyword in config.get("keywords", []):
            if keyword.lower() in raw_data:
                return True
        for sig in config.get("AttackSignatures", []):
            if sig.lower() in raw_data:
                return True

    return False


def send_icmp_unreachable(ip_packet):
    ip_src = ip_packet[IP].src
    ip_dst = ip_packet[IP].dst
    icmp_response = IP(src=ip_dst, dst=ip_src) / ICMP(type=3)
    send(icmp_response, verbose=False)
    print(f"[!] ICMP Destination Unreachable sent to {ip_src}")
    log_alert(f"ICMP Destination Unreachable sent to {ip_src}")


def process_packet(pkt):
    try:
        payload = IP(pkt.get_payload())
        packet_info(payload)

        if is_malicious(payload, latest_config):
            msg = f"[!] Malicious packet detected from {payload[IP].src}. Sending response."
            print(msg)
            logging.warning(msg)
            log_alert(msg)
            send_icmp_unreachable(payload)
            pkt.drop()
        else:
            pkt.accept()
    except Exception as e:
        print(f"[!] Error processing packet: {e}")
        logging.error(f"Error processing packet: {e}")
        pkt.accept()


class ConfigChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(FIREWALL_RULES_FILE):
            print("[*] Configuration file changed. Reloading...")
            logging.info("Reloaded firewall rules due to file modification.")
            load_config()


def main():
    print("[*] Setting up iptables rules...")
    load_firewall_rules()
    load_config()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)

    observer = Observer()
    observer.schedule(ConfigChangeHandler(), path=".", recursive=False)
    observer.start()

    def cleanup(signum, frame):
        print("\n[*] Caught interrupt. Cleaning up...")
        nfqueue.unbind()
        flush_iptables()
        observer.stop()
        observer.join()
        exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print("[*] Packet redirector running. Press Ctrl+C to stop.")
    nfqueue.run()


if __name__ == "__main__":
    main()

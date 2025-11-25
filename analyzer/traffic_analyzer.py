# analyzer/traffic_analyzer.py
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import rdpcap, sniff, TCP, UDP, ICMP, ARP, Ether, IP
from tabulate import tabulate
import logging
from collections import Counter, defaultdict
import time
import os

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# -------------------------
# Loading / live capture
# -------------------------
def load_packets(pcap_file, live_mode=False, packet_count=100):
    if live_mode:
        print(f"Capturing {packet_count} live packets... (press CTRL+C to stop early)")
        packets = sniff(count=packet_count)
    else:
        if not pcap_file:
            print("No PCAP file provided.")
            return []
        packets = rdpcap(pcap_file)
        print(f"Loaded {len(packets)} packets from {pcap_file}")
    return packets

# -------------------------
# Feature extraction helpers
# -------------------------
def detect_protocol(pkt):
    """Return protocol label: TCP, UDP, ICMP, ARP, or IP (fallback)"""
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP):
        return "IP"
    return "OTHER"

def calculate_bandwidth(packets):
    return sum(len(pkt) for pkt in packets)

def get_protocol_distribution(packets):
    counts = Counter()
    for pkt in packets:
        proto = detect_protocol(pkt)
        counts[proto] += 1
    df = pd.DataFrame(list(counts.items()), columns=["Protocol", "Count"])
    if df["Count"].sum() > 0:
        df["Percentage"] = (df["Count"] / df["Count"].sum()) * 100
    else:
        df["Percentage"] = 0.0
    df = df.sort_values("Count", ascending=False).reset_index(drop=True)
    return df

def get_ip_communication_table(packets):
    rows = Counter()
    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            rows[(src, dst)] += 1
    df = pd.DataFrame([{"Source IP": s, "Destination IP": d, "Count": c} for (s, d), c in rows.items()])
    if df.empty:
        return df
    return df.sort_values("Count", ascending=False).reset_index(drop=True)

def get_ip_protocol_shares(packets):
    rows = Counter()
    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = detect_protocol(pkt)
            rows[(src, dst, proto)] += 1
    df = pd.DataFrame([{"Source IP": s, "Destination IP": d, "Protocol": p, "Count": c} for (s, d, p), c in rows.items()])
    if df.empty:
        return df
    return df.sort_values(["Count"], ascending=False).reset_index(drop=True)

def get_port_distribution(packets, top_n=10):
    rows = Counter()
    for pkt in packets:
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            rows[f"TCP/{dport}"] += 1
            rows[f"TCP_sport/{sport}"] += 0  # keep key potential
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            rows[f"UDP/{dport}"] += 1
    if not rows:
        return pd.DataFrame(columns=["Port", "Count"])
    df = pd.DataFrame(list(rows.items()), columns=["Port", "Count"]).sort_values("Count", ascending=False).head(top_n).reset_index(drop=True)
    return df

# -------------------------
# Export / Print / Visualize
# -------------------------
def export_results(protocol_df, ip_comm_table, export_format):
    os.makedirs("output", exist_ok=True)
    if export_format == "csv":
        protocol_df.to_csv("output/protocol_distribution.csv", index=False)
        ip_comm_table.to_csv("output/ip_communications.csv", index=False)
        print("Exported results to CSV (output/).")
    elif export_format == "json":
        protocol_df.to_json("output/protocol_distribution.json", orient="records")
        ip_comm_table.to_json("output/ip_communications.json", orient="records")
        print("Exported results to JSON (output/).")

def print_results(total_bw, protocol_df, ip_comm_table, ip_protocols):
    unit = "KB" if total_bw < 1e6 else "MB"
    bw = total_bw / 1e3 if unit == "KB" else total_bw / 1e6
    logger.info(f"Total bandwidth used: {bw:.2f} {unit}\n")

    logger.info("Protocol Distribution:\n")
    if not protocol_df.empty:
        logger.info(tabulate(protocol_df[["Protocol", "Percentage"]].reset_index(drop=True), headers=["Protocol", "Percentage"], tablefmt="grid"))
    else:
        logger.info("No protocol data.")

    logger.info("\nTop IP Communications:\n")
    if not ip_comm_table.empty:
        logger.info(tabulate(ip_comm_table.head(20), headers="keys", tablefmt="grid"))
    else:
        logger.info("No IP communications.")

    logger.info("\nProtocol share between IPs:\n")
    if not ip_protocols.empty:
        logger.info(tabulate(ip_protocols.head(20), headers="keys", tablefmt="grid"))
    else:
        logger.info("No IP-protocol shares.")

def visualize_results(protocol_df, ip_comm_table, port_df=None):
    # Protocol pie
    if protocol_df is not None and not protocol_df.empty:
        plt.figure(figsize=(6,6))
        plt.title("Protocol Distribution")
        plt.pie(protocol_df["Count"], labels=protocol_df["Protocol"], autopct="%1.1f%%")
        plt.tight_layout()
        plt.show()

    # Top IP communications
    if ip_comm_table is not None and not ip_comm_table.empty:
        top = ip_comm_table.head(10)
        labels = top["Source IP"] + " → " + top["Destination IP"]
        plt.figure(figsize=(9,4))
        plt.bar(labels, top["Count"])
        plt.title("Top IP Communications")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.show()

    # Top ports
    if port_df is not None and not port_df.empty:
        plt.figure(figsize=(8,4))
        plt.bar(port_df["Port"].astype(str), port_df["Count"])
        plt.title("Top Ports")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.show()

# -------------------------
# Main analyze function (entry point)
# -------------------------
def main(pcap_file, threshold=None, export_format=None, visualize=False, live_mode=False, packet_count=100):
    packets = load_packets(pcap_file, live_mode, packet_count)
    if not packets:
        return None

    total_bw = calculate_bandwidth(packets)
    protocol_df = get_protocol_distribution(packets)
    ip_comm_table = get_ip_communication_table(packets)
    ip_protocols = get_ip_protocol_shares(packets)
    port_df = get_port_distribution(packets, top_n=10)

    if export_format:
        export_results(protocol_df, ip_comm_table, export_format)

    if visualize:
        visualize_results(protocol_df, ip_comm_table, port_df)

    return total_bw, protocol_df, ip_comm_table, ip_protocols, port_df

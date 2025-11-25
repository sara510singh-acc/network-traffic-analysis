# generate_sample_pcap.py
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, wrpcap
import random
import os

def generate_sample_pcap(filename="data/fake_attack.pcap", count=250):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    packets = []

    # Port scan simulation (TCP SYN-like)
    for port in range(20, 30):
        eth = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
        pkt = eth / IP(src="192.168.1.10", dst="192.168.1.100") / TCP(dport=port, flags="S")
        packets.append(pkt)

    # UDP flood simulation
    for _ in range(50):
        eth = Ether(src=RandMAC(), dst=RandMAC())
        pkt = eth / IP(src="10.0.0.5", dst="10.0.0.200") / UDP(dport=random.randint(1000, 2000))
        packets.append(pkt)

    # ICMP sweep
    for i in range(5):
        eth = Ether(src=RandMAC(), dst=RandMAC())
        pkt = eth / IP(src=f"172.16.0.{i+1}", dst="172.16.0.100") / ICMP()
        packets.append(pkt)

    # ARP spoofing (ARP is link-layer)
    for _ in range(10):
        eth = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
        pkt = eth / ARP(op=2, hwsrc=eth.src, psrc="192.168.1.1", pdst="192.168.1.100")
        packets.append(pkt)

    # Some normal TCP traffic (HTTP/HTTPS style)
    for _ in range(30):
        eth = Ether(src=RandMAC(), dst=RandMAC())
        pkt = eth / IP(src=f"10.1.0.{random.randint(2,250)}", dst=f"10.1.0.{random.randint(2,250)}") / TCP(dport=random.choice([80, 443, 22]), flags="PA")
        packets.append(pkt)

    # Shuffle so not grouped
    random.shuffle(packets)

    wrpcap(filename, packets)
    print(f"Generated {len(packets)} packets in {filename}")

# helper for randomized MACs
from scapy.all import RandMAC

if __name__ == "__main__":
    generate_sample_pcap()

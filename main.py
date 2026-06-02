#!/usr/bin/env python3

"""
Network Packet Analyzer
Author: Ritish Giriprasad

Features:
- Live packet capture using Scapy
- Protocol filtering (TCP, UDP, ICMP, ARP)
- Source/Destination IP extraction
- Source/Destination Port extraction
- TCP Flag analysis
- Packet counter
- Timestamped output
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
import argparse
import signal
import sys

packet_count = 0


# --------------------------------------------------
# Protocol Detection
# --------------------------------------------------

def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(ARP):
        return "ARP"
    else:
        return "OTHER"


# --------------------------------------------------
# TCP Flag Decoder
# --------------------------------------------------

def decode_tcp_flags(flags):
    flag_list = []

    if flags & 0x01:
        flag_list.append("FIN")

    if flags & 0x02:
        flag_list.append("SYN")

    if flags & 0x04:
        flag_list.append("RST")

    if flags & 0x08:
        flag_list.append("PSH")

    if flags & 0x10:
        flag_list.append("ACK")

    if flags & 0x20:
        flag_list.append("URG")

    return ",".join(flag_list) if flag_list else "-"


# --------------------------------------------------
# Packet Processor
# --------------------------------------------------

def process_packet(packet):
    global packet_count

    packet_count += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

    protocol = get_protocol(packet)

    src_ip = "-"
    dst_ip = "-"

    src_port = "-"
    dst_port = "-"

    tcp_flags = "-"

    try:

        # -------------------------
        # IP Layer
        # -------------------------
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        # -------------------------
        # TCP Layer
        # -------------------------
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = decode_tcp_flags(packet[TCP].flags)

        # -------------------------
        # UDP Layer
        # -------------------------
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        print(
            f"[{packet_count:05}] "
            f"{timestamp} | "
            f"{protocol:<5} | "
            f"{src_ip}:{src_port}  -->  "
            f"{dst_ip}:{dst_port} | "
            f"Flags: {tcp_flags}"
        )

    except Exception as e:
        print(f"[ERROR] Packet processing failed: {e}")


# --------------------------------------------------
# Sniffer
# --------------------------------------------------

def start_sniffer(interface, protocol_filter):

    print("=" * 100)
    print("NETWORK PACKET ANALYZER")
    print("=" * 100)

    print(f"Interface : {interface}")
    print(f"Filter    : {protocol_filter if protocol_filter else 'None'}")
    print("Press CTRL+C to stop")
    print("=" * 100)

    try:

        sniff(
            iface=interface,
            prn=process_packet,
            store=False,
            filter=protocol_filter
        )

    except PermissionError:
        print("\n[ERROR] Permission denied.")
        print("Run with sudo.")

    except Exception as e:
        print(f"\n[ERROR] {e}")


# --------------------------------------------------
#  Exit
# --------------------------------------------------

def signal_handler(sig, frame):
    print("\n")
    print("=" * 50)
    print("Capture Stopped")
    print(f"Total Packets Captured: {packet_count}")
    print("=" * 50)
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


# --------------------------------------------------
# CLI Arguments
# --------------------------------------------------

def parse_arguments():

    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer using Scapy"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Network interface (example: en0)"
    )

    parser.add_argument(
        "-f",
        "--filter",
        choices=["tcp", "udp", "icmp", "arp"],
        help="Protocol filter"
    )

    return parser.parse_args()


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    args = parse_arguments()

    start_sniffer(
        interface=args.interface,
        protocol_filter=args.filter
    )


if __name__ == "__main__":
    main()

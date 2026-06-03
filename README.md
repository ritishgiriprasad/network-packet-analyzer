# Network Packet Analyzer

A real-time network packet analyzer built in Python using Scapy.

This project captures live network traffic from a selected network interface and displays packet information in real time, including protocol details, IP addresses, ports, and TCP flags.

Features

- Live packet capture
- Real-time packet summaries
- Protocol detection
  - TCP
  - UDP
  - ICMP
  - ARP
- Source and destination IP extraction
- Source and destination port extraction
- TCP flag decoding
  - SYN
  - ACK
  - FIN
  - RST
  - PSH
  - URG
- Protocol filtering
- Packet counting
- Timestamped output
- Error handling

---

Technologies Used

- Python 3
- Scapy

---

Installation

Clone the repository:

bash
git clone https://github.com/ritishgiriprasad/network-packet-analyzer.git
cd network-packet-analyzer


Install dependencies:

bash
python3 -m pip install -r requirements.txt


---
Usage

Find Available Network Interfaces

macOS / Linux:

bash
ifconfig


Run Packet Analyzer

bash
sudo python3 main.py -i en1


Filter TCP Traffic

bash
sudo python3 main.py -i en1 -f tcp


Filter UDP Traffic

bash
sudo python3 main.py -i en1 -f udp


Filter ICMP Traffic

bash
sudo python3 main.py -i en1 -f icmp


---

## Example Output

text
====================================================================================================
NETWORK PACKET ANALYZER
====================================================================================================

[00001] 14:25:01 | TCP   | 192.168.1.5:53422 --> 142.250.xxx.xxx:443 | Flags: SYN
[00002] 14:25:01 | TCP   | 142.250.xxx.xxx:443 --> 192.168.1.5:53422 | Flags: SYN,ACK
[00003] 14:25:01 | TCP   | 192.168.1.5:53422 --> 142.250.xxx.xxx:443 | Flags: ACK


---

## Project Structure

text
network-packet-analyzer/
│
├── main.py
├── requirements.txt
├── README.md
└── screenshots/


---

## Disclaimer

-This project is intended for educational purposes and should only be used on networks you own or are authorized to analyze.
-Built as a networking learning project while exploring packet analysis and Scapy.

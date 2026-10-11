# Packet Sniffer

A small Python command-line project for learning how packet capture works. It prints packet timestamps, source and destination addresses, transport ports, protocol labels, and frame lengths. It does not inspect or save packet payloads.

## Requirements

- Python 3.10 or newer
- Scapy (installed from `requirements.txt`)
- A packet capture driver: Npcap on Windows, or libpcap on most Linux/macOS systems
- Administrator/root or suitable packet-capture permissions

## Setup

```text
python -m pip install -r requirements.txt
```

On Windows, install Npcap from its official site. During installation, enable the option that allows Npcap to be used by non-administrators only if that matches your machine's security policy. Open an elevated terminal if capture permissions require it.

## Usage

List interfaces:

```text
python packet_sniffer.py --list-interfaces
```

Capture on an interface (stop with Ctrl+C):

```text
python packet_sniffer.py --interface "Wi-Fi"
```

Capture a limited number of packets or for a limited time:

```text
python packet_sniffer.py --interface "Ethernet" --count 50
python packet_sniffer.py --interface "Wi-Fi" --timeout 30
```

Use a BPF filter and optionally save summaries to CSV:

```text
python packet_sniffer.py --interface "Wi-Fi" --filter "tcp port 443" --timeout 60 --output capture.csv
```

Filter examples include `udp`, `icmp`, `host 192.0.2.10`, and `port 53`. Filter support depends on the installed capture driver.

## Scope and privacy

Use this only on networks and devices you own or are authorized to monitor. The program reports header-level metadata and total captured packet length. It does not record packet contents. CSV output contains the same metadata shown in the terminal.

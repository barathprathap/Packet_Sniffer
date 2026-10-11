#!/usr/bin/env python3
"""Educational packet sniffer that reports headers and lengths, never payloads."""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scapy.all import ARP, ICMP, ICMPv6EchoRequest, IP, IPv6, TCP, UDP, conf, get_if_list, sniff
except ImportError:
    print("Scapy is required. Install dependencies with: python -m pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2)


FIELDS = ("time_utc", "src", "dst", "protocol", "src_port", "dst_port", "length")


def packet_row(packet: Any) -> dict[str, str | int]:
    """Extract a compact packet summary without accessing raw payload bytes."""
    src, dst, protocol = "?", "?", "OTHER"
    src_port: str | int = ""
    dst_port: str | int = ""

    if packet.haslayer(IP):
        layer = packet[IP]
        src, dst = layer.src, layer.dst
    elif packet.haslayer(IPv6):
        layer = packet[IPv6]
        src, dst = layer.src, layer.dst
    elif packet.haslayer(ARP):
        layer = packet[ARP]
        src, dst, protocol = layer.psrc, layer.pdst, "ARP"

    if packet.haslayer(TCP):
        layer = packet[TCP]
        protocol, src_port, dst_port = "TCP", layer.sport, layer.dport
    elif packet.haslayer(UDP):
        layer = packet[UDP]
        protocol, src_port, dst_port = "UDP", layer.sport, layer.dport
    elif packet.haslayer(ICMP) or packet.haslayer(ICMPv6EchoRequest):
        protocol = "ICMP"
    elif protocol != "ARP" and packet.haslayer(IP):
        protocol = "IPv4"
    elif protocol != "ARP" and packet.haslayer(IPv6):
        protocol = "IPv6"

    captured_at = getattr(packet, "time", None)
    if captured_at is None:
        time_utc = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    else:
        time_utc = datetime.fromtimestamp(float(captured_at), timezone.utc).isoformat(timespec="milliseconds")

    return {
        "time_utc": time_utc,
        "src": src,
        "dst": dst,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": len(packet),
    }


def print_interfaces() -> None:
    print("Available interfaces:")
    for name in get_if_list():
        print(f"  {name}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Show packet metadata on a network you own or are authorized to monitor. Payloads are not saved."
    )
    parser.add_argument("-i", "--interface", help="Interface name (default: Scapy's default interface)")
    parser.add_argument("-f", "--filter", dest="capture_filter", help="Optional BPF capture filter, e.g. 'tcp port 443'")
    parser.add_argument("-c", "--count", type=int, default=0, help="Stop after this many packets (0 means unlimited)")
    parser.add_argument("-t", "--timeout", type=int, help="Stop after this many seconds")
    parser.add_argument("-o", "--output", type=Path, help="Write metadata rows to a CSV file")
    parser.add_argument("--list-interfaces", action="store_true", help="List interfaces and exit")
    args = parser.parse_args()

    if args.count < 0 or (args.timeout is not None and args.timeout <= 0):
        parser.error("count must be zero or greater, and timeout must be a positive number")
    if args.list_interfaces:
        print_interfaces()
        return 0

    writer = None
    csv_file = None
    if args.output:
        try:
            csv_file = args.output.open("w", newline="", encoding="utf-8")
        except OSError as exc:
            print(f"Cannot open CSV output: {exc}", file=sys.stderr)
            return 2
        writer = csv.DictWriter(csv_file, fieldnames=FIELDS)
        writer.writeheader()

    print("Capturing packet metadata only. Press Ctrl+C to stop.")
    print("Only monitor networks and devices you own or have permission to inspect.")
    print(f"Interface: {args.interface or conf.iface}")
    if args.capture_filter:
        print(f"Filter: {args.capture_filter}")
    print("TIME (UTC)                         SOURCE              DESTINATION         PROTOCOL  SIZE")

    def on_packet(packet: Any) -> None:
        row = packet_row(packet)
        source = str(row["src"])
        destination = str(row["dst"])
        if row["src_port"]:
            source += f":{row['src_port']}"
            destination += f":{row['dst_port']}"
        print(f"{row['time_utc']:<34} {source:<19} {destination:<19} {row['protocol']:<8} {row['length']}")
        if writer:
            writer.writerow(row)
            csv_file.flush()

    try:
        sniff(
            iface=args.interface,
            filter=args.capture_filter,
            prn=on_packet,
            store=False,
            count=args.count,
            timeout=args.timeout,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except PermissionError:
        print("Capture needs elevated privileges. Run as administrator/root and check the capture driver.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        if sys.platform == "win32":
            print("On Windows, install Npcap and allow non-admin packet capture if appropriate.", file=sys.stderr)
        return 1
    finally:
        if csv_file:
            csv_file.close()

    print("Capture complete.")
    if args.output:
        print(f"Metadata CSV: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

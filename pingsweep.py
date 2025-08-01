#!/usr/bin/env python3

from scapy.all import ICMP, IP, sr1
import ipaddress
import argparse
import sys

def get_targets(target):
    try:
        return list(ipaddress.ip_network(target, strict=False).hosts())
    except ValueError as e:
        print(f"[!] Invalid target format: {e}")
        sys.exit(1)

def ping_host(ip):
    pkt = IP(dst=str(ip)) / ICMP()
    resp = sr1(pkt, timeout=1, verbose=0)
    return resp is not None

def main():
    parser = argparse.ArgumentParser(description="Ping sweep to detect live hosts")
    parser.add_argument("target", help="Target subnet/IP (e.g. 192.168.1.0/24 or 192.168.1.100)")
    parser.add_argument("-o", "--output", required=True, help="Output filename to save live hosts (e.g. live_hosts.txt)")
    args = parser.parse_args()

    targets = get_targets(args.target)
    print(f"[*] Scanning {len(targets)} hosts...")

    live_hosts = []
    for ip in targets:
        if ping_host(ip):
            print(f"[+] Host is up: {ip}")
            live_hosts.append(str(ip))

    if live_hosts:
        with open(args.output, "w") as f:
            for host in live_hosts:
                f.write(f"{host}\n")
        print(f"\n[+] Saved {len(live_hosts)} live hosts to: {args.output}")
    else:
        print("[-] No live hosts found.")

if __name__ == "__main__":
    main()

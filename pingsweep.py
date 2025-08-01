#!/usr/bin/env python3

from scapy.all import ICMP, IP, sr1
import ipaddress
import argparse
import concurrent.futures
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_targets(target):
    try:
        return list(ipaddress.ip_network(target, strict=False).hosts())
    except ValueError as e:
        print(f"[!] Invalid target format: {e}")
        exit(1)

def ping_host(ip, timeout=1):
    try:
        pkt = IP(dst=str(ip)) / ICMP()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        return str(ip) if resp else None
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser(description="Fast Ping Sweep")
    parser.add_argument("target", help="Target subnet or IP (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", help="Save live IPs to file")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")
    args = parser.parse_args()

    targets = get_targets(args.target)
    print(f"[*] Scanning {len(targets)} IPs using {args.threads} threads...")

    live_hosts = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = list(executor.map(ping_host, targets))

    for ip in results:
        if ip:
            print(f"[+] Host is up: {ip}")
            live_hosts.append(ip)

    if args.output:
        with open(args.output, "w") as f:
            for ip in live_hosts:
                f.write(ip + "\n")
        print(f"\n[+] Saved live hosts to: {args.output}")
    else:
        print(f"\n[+] {len(live_hosts)} hosts are up.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
================================================================================
 Project     : CodeAlpha Basic Network Sniffer
 Track       : Cyber Security Internship Task 1
 Repository  : CodeAlpha_BasicNetworkSniffer
 Developer   : Cyber Jerry (Syed Jareer Ahmad Shah Jaffri)
 Version     : 2.1.0-PRO
 Description : Multi-threaded OSI Layer 3/4 packet inspection engine with 
               real-time protocol dissection, ASCII sanitization, and PCAP dump.
================================================================================
"""

import argparse
import sys
import os
import time
from datetime import datetime
from collections import Counter

# Scapy packet manipulation core
from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw

# ==============================================================================
# TERMINAL UI & ANSI COLOR PALETTE
# ==============================================================================
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    
    # Core Branding
    CYAN    = "\033[38;5;51m"
    BLUE    = "\033[38;5;39m"
    GREEN   = "\033[38;5;82m"
    YELLOW  = "\033[38;5;220m"
    RED     = "\033[38;5;196m"
    PURPLE  = "\033[38;5;135m"
    GRAY    = "\033[38;5;244m"
    WHITE   = "\033[38;5;255m"

# Windows VT100 Support Activation
if os.name == 'nt':
    os.system('')

BANNER = f"""{Colors.CYAN}{Colors.BOLD}
  ██████╗██╗   ██╗██████╗ ███████╗██████╗      ██╗███████╗██████╗ ██████╗ ██╗   ██╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗     ██║██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝     ██║█████╗  ██████╔╝██████╔╝ ╚████╔╝ 
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██   ██║██╔══╝  ██╔══██╗██╔══██╗  ╚██╔╝  
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚█████╔╝███████╗██║  ██║██║  ██║   ██║   
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
{Colors.BLUE}               -= ADVANCED PACKET AUDITOR & NETWORK SNIFFER =-
{Colors.GRAY}            [ Version 2.1.0-PRO | CodeAlpha Security Lab Assessment ]
{Colors.RESET}"""

# Global telemetry buffers
stats = Counter()
start_timestamp = None

# ==============================================================================
# PAYLOAD PARSER & FORMATTER
# ==============================================================================
def format_payload(payload_bytes, limit=48):
    """Sanitize and format raw byte payloads into human-readable ASCII text."""
    filtered = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload_bytes[:limit])
    if len(payload_bytes) > limit:
        filtered += f"{Colors.GRAY} ... (+{len(payload_bytes) - limit} bytes){Colors.RESET}"
    return filtered

# ==============================================================================
# PACKET DISSECTOR ENGINE
# ==============================================================================
def packet_callback(pkt, payload_limit=48, save_list=None):
    if save_list is not None:
        save_list.append(pkt)

    timestamp = datetime.now().strftime("%H:%M:%S")

    # Layer 3 Processing (IPv4 / IPv6)
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ttl = ip_layer.ttl
        length = ip_layer.len
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ttl = ip_layer.hlim
        length = ip_layer.plen
    else:
        return

    # Layer 4 Processing & Output Styling
    if TCP in pkt:
        stats["TCP"] += 1
        tcp = pkt[TCP]
        tag = f"{Colors.GREEN}[TCP]{Colors.RESET}"
        print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {tag} {src_ip}:{Colors.YELLOW}{tcp.sport}{Colors.RESET} -> {dst_ip}:{Colors.YELLOW}{tcp.dport}{Colors.RESET} | ttl={ttl} len={length} flags={Colors.PURPLE}{tcp.flags}{Colors.RESET} seq={tcp.seq}")

    elif UDP in pkt:
        stats["UDP"] += 1
        udp = pkt[UDP]
        tag = f"{Colors.BLUE}[UDP]{Colors.RESET}"
        print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {tag} {src_ip}:{Colors.YELLOW}{udp.sport}{Colors.RESET} -> {dst_ip}:{Colors.YELLOW}{udp.dport}{Colors.RESET} | ttl={ttl} len={length}")

        # Deep DNS Query Parsing
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            dns_query = pkt.getlayer(DNSQR)
            if dns_query:
                qname = dns_query.qname.decode('utf-8', errors='ignore')
                print(f"      {Colors.CYAN}└── [DNS QUERY]{Colors.RESET} {Colors.WHITE}{qname}{Colors.RESET}")

    elif ICMP in pkt:
        stats["ICMP"] += 1
        icmp = pkt[ICMP]
        tag = f"{Colors.YELLOW}[ICMP]{Colors.RESET}"
        print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {tag} {src_ip} -> {dst_ip} | ttl={ttl} len={length} type={icmp.type} code={icmp.code}")

    else:
        stats["OTHER"] += 1
        tag = f"{Colors.GRAY}[IP]{Colors.RESET}"
        print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {tag} {src_ip} -> {dst_ip} | proto={ip_layer.proto} ttl={ttl} len={length}")

    # Payload Preview Layer
    if Raw in pkt:
        payload_data = pkt[Raw].load
        clean_text = format_payload(payload_data, limit=payload_limit)
        print(f"      {Colors.PURPLE}└── [DATA]{Colors.RESET} {clean_text}")

# ==============================================================================
# AUDIT SUMMARY GENERATOR
# ==============================================================================
def render_summary():
    elapsed = round(time.time() - start_timestamp, 2) if start_timestamp else 0
    total = sum(stats.values())

    print("\n" + Colors.CYAN + "=" * 68 + Colors.RESET)
    print(f"{Colors.BOLD}{Colors.WHITE}                 SESSION TRAFFIC AUDIT METRICS{Colors.RESET}")
    print(Colors.CYAN + "=" * 68 + Colors.RESET)
    print(f" {Colors.BOLD}Runtime Duration{Colors.RESET}    : {elapsed} seconds")
    print(f" {Colors.BOLD}Total Packets{Colors.RESET}       : {total}")
    print(Colors.CYAN + "-" * 68 + Colors.RESET)

    for proto, count in stats.items():
        pct = (count / total * 100) if total > 0 else 0
        bar = "█" * int(pct // 5)
        print(f" • {proto:<6} : {count:<5} | {pct:>5.1f}% | {Colors.BLUE}{bar:<20}{Colors.RESET}")

    print(Colors.CYAN + "=" * 68 + Colors.RESET + "\n")

# ==============================================================================
# ENTRY POINT
# ==============================================================================
def main():
    global start_timestamp

    parser = argparse.ArgumentParser(
        description="Cyber Jerry Enterprise Network Sniffer (CodeAlpha Security Lab)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--interface", help="Target adapter (e.g., eth0, Wi-Fi)", default=None)
    parser.add_argument("-c", "--count", type=int, help="Stop capture after N packets (default: continuous)", default=0)
    parser.add_argument("-f", "--filter", help="Kernel-level BPF filter rule (e.g., 'tcp port 80', 'icmp')", default="")
    parser.add_argument("-w", "--write", help="Write captured frames to a .pcap forensic dump", default=None)
    parser.add_argument("-l", "--limit", type=int, help="Payload preview cutoff limit (default: 48 bytes)", default=48)

    args = parser.parse_args()

    # Clear screen and show branding
    os.system('cls' if os.name == 'nt' else 'clear')
    print(BANNER)

    print(f"{Colors.BOLD}[*] Security Engine Initialization:{Colors.RESET}")
    print(f"    • Bound Interface : {Colors.YELLOW}{args.interface if args.interface else 'Default Adapter'}{Colors.RESET}")
    print(f"    • BPF Kernel Rule : {Colors.YELLOW}{args.filter if args.filter else 'None (Promiscuous All)'}{Colors.RESET}")
    print(f"    • Packet Quota    : {Colors.YELLOW}{str(args.count) if args.count > 0 else 'Unlimited (Ctrl+C to abort)'}{Colors.RESET}")
    if args.write:
        print(f"    • PCAP Target     : {Colors.GREEN}{args.write}{Colors.RESET}")
    print(f"\n{Colors.GREEN}[+] Listening for live network streams...{Colors.RESET}\n")

    pcap_buffer = [] if args.write else None
    start_timestamp = time.time()

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=lambda pkt: packet_callback(pkt, payload_limit=args.limit, save_list=pcap_buffer),
            count=args.count,
            store=bool(args.write)
        )
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Session aborted by operator.{Colors.RESET}")
    except PermissionError:
        print(f"\n{Colors.RED}[-] Critical: Socket access denied. Elevate terminal permissions (Run as Admin / sudo).{Colors.RESET}")
        sys.exit(1)
    except Exception as err:
        print(f"\n{Colors.RED}[-] Engine Runtime Failure: {err}{Colors.RESET}")
        sys.exit(1)
    finally:
        render_summary()
        if args.write and pcap_buffer:
            print(f"{Colors.CYAN}[*] Flushing buffer to forensic container '{args.write}'...{Colors.RESET}")
            wrpcap(args.write, pcap_buffer)
            print(f"{Colors.GREEN}[+] Forensics dump written successfully.{Colors.RESET}")

if __name__ == "__main__":
    main()
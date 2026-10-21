    #!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
================================================================================
 Network Intrusion Detection System (NIDS)
 Developer   : Cyber Jerry
 Description : Multi-threaded OSI Layer 3/4 Real-Time NIDS Engine with 
               Stateful Detection, Signature-Based DPI, and Alert Logging.
================================================================================
"""

import argparse
import sys
import os
import time
import re
from datetime import datetime
from collections import Counter, defaultdict

# Scapy packet manipulation core
from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw

# ==============================================================================
# TERMINAL UI & ANSI COLOR PALETTE
# ==============================================================================
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    
    # Core Branding (Blue Theme)
    CYAN    = "\033[38;5;51m"
    BLUE    = "\033[38;5;39m"
    YELLOW  = "\033[38;5;220m"
    RED     = "\033[38;5;196m"
    PURPLE  = "\033[38;5;135m"
    GRAY    = "\033[38;5;244m"
    WHITE   = "\033[38;5;255m"
    BG_RED  = "\033[48;5;196m\033[38;5;255m"

# Windows VT100 Support Activation
if os.name == 'nt':
    os.system('')

BANNER = f"""{Colors.CYAN}{Colors.BOLD}
 ██████╗██╗   ██╗██████╗ ███████╗██████╗     ██╗███████╗██████╗ ██████╗ ██╗   ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██║██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██║█████╗  ██████╔╝██████╔╝ ╚████╔╝ 
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██  ██║██╔══╝  ██╔══██╗██╔══██╗  ╚██╔╝  
╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚█████╔╝███████╗██║  ██║██║  ██║   ██║   
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
{Colors.BLUE}            -= REAL-TIME NETWORK INTRUSION DETECTION SYSTEM =-
{Colors.CYAN}                       [ Developer: Cyber Jerry ]
{Colors.RESET}"""

# Global telemetry & Detection state buffers
stats = Counter()
threat_stats = Counter()
start_timestamp = None

# Stateful Tracker Buffers for Rate Anomalies
scan_tracker = defaultdict(set)        # {src_ip: {dst_port1, dst_port2, ...}}
syn_flood_tracker = defaultdict(list)   # {src_ip: [timestamp1, timestamp2, ...]}
icmp_flood_tracker = defaultdict(list)  # {src_ip: [timestamp1, timestamp2, ...]}

# Detection Threshold Parameters
PORT_SCAN_THRESHOLD = 15      # Unique ports accessed within window
SYN_FLOOD_THRESHOLD = 20      # SYN packets per 2 seconds
ICMP_FLOOD_THRESHOLD = 15     # ICMP packets per 2 seconds
TIME_WINDOW = 2.0             # Sliding window in seconds

# Refined Deep Packet Inspection Signatures (Accurate & Context Aware)
ATTACK_SIGNATURES = {
    "SQL Injection (SQLi)": re.compile(r"(?i)((\%27|\')\s*(OR|AND)\s*(\%27|\'|\d)=\d|UNION\s+SELECT|SELECT\s+.*\s+FROM|INSERT\s+INTO|DROP\s+TABLE)"),
    "Cross-Site Scripting (XSS)": re.compile(r"(?i)(<script>|\%3Cscript\%3E|javascript:|alert\(|onerror=)"),
    "Directory Traversal / LFI": re.compile(r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|c:\\boot.ini)"),
    "Suspicious Shell/Command Access": re.compile(r"(?i)(cmd\.exe|powershell|\/bin\/sh|\/bin\/bash|wget\s|curl\s)")
}

LOG_FILE = "nids_alerts.log"

# ==============================================================================
# LOGGING & ALERTING MECHANISM
# ==============================================================================
def log_alert(alert_type, src_ip, dst_info, details, severity="HIGH"):
    """Format, display, and record intrusion alerts to console and log file."""
    threat_stats[alert_type] += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    alert_fmt = f"[{timestamp}] [{severity}] [{alert_type}] Src: {src_ip} -> Dst: {dst_info} | Details: {details}"
    
    # Print to Console
    color = Colors.BG_RED if severity == "CRITICAL" else Colors.RED
    print(f"\n{color} [!] INTRUSION DETECTED [{alert_type}] {Colors.RESET}")
    print(f"    {Colors.YELLOW}• Timestamp {Colors.RESET}: {timestamp}")
    print(f"    {Colors.YELLOW}• Threat    {Colors.RESET}: {Colors.BOLD}{alert_type}{Colors.RESET}")
    print(f"    {Colors.YELLOW}• Source    {Colors.RESET}: {src_ip}")
    print(f"    {Colors.YELLOW}• Target    {Colors.RESET}: {dst_info}")
    print(f"    {Colors.YELLOW}• Details   {Colors.RESET}: {details}\n")
    
    # Save Alert to File
    with open(LOG_FILE, "a") as f:
        f.write(alert_fmt + "\n")

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
# STATEFUL DETECTION ENGINE
# ==============================================================================
def analyze_packet_for_threats(pkt, src_ip, dst_ip, sport, dport):
    """Execute signature analysis and rate anomaly heuristics."""
    now = time.time()

    # 1. Port Scan Detection Logic
    if dport is not None:
        scan_tracker[src_ip].add(dport)
        if len(scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
            log_alert(
                "Port Scanning Activity", 
                src_ip, 
                f"{dst_ip}", 
                f"Probed {len(scan_tracker[src_ip])} unique ports", 
                severity="HIGH"
            )
            scan_tracker[src_ip].clear()

    # 2. TCP SYN Flood Detection
    if TCP in pkt and pkt[TCP].flags == 'S':
        syn_flood_tracker[src_ip].append(now)
        syn_flood_tracker[src_ip] = [t for t in syn_flood_tracker[src_ip] if now - t <= TIME_WINDOW]
        
        if len(syn_flood_tracker[src_ip]) > SYN_FLOOD_THRESHOLD:
            log_alert(
                "TCP SYN Flood Attack", 
                src_ip, 
                f"{dst_ip}:{dport}", 
                f"Burst of {len(syn_flood_tracker[src_ip])} SYN packets within {TIME_WINDOW}s", 
                severity="CRITICAL"
            )
            syn_flood_tracker[src_ip].clear()

    # 3. ICMP Flood Detection
    if ICMP in pkt:
        icmp_flood_tracker[src_ip].append(now)
        icmp_flood_tracker[src_ip] = [t for t in icmp_flood_tracker[src_ip] if now - t <= TIME_WINDOW]
        
        if len(icmp_flood_tracker[src_ip]) > ICMP_FLOOD_THRESHOLD:
            log_alert(
                "ICMP Flood / Ping Sweep", 
                src_ip, 
                f"{dst_ip}", 
                f"High-rate ICMP volume ({len(icmp_flood_tracker[src_ip])} pkts/{TIME_WINDOW}s)", 
                severity="MEDIUM"
            )
            icmp_flood_tracker[src_ip].clear()

    # 4. Signature-Based Deep Packet Inspection (DPI)
    if Raw in pkt:
        payload_bytes = pkt[Raw].load
        try:
            payload_str = payload_bytes.decode('utf-8', errors='ignore')
            # Ignore encrypted binary streams (e.g., HTTPS/TLS on port 443) for text injection signatures
            if dport != 443 and sport != 443:
                for attack_name, pattern in ATTACK_SIGNATURES.items():
                    if pattern.search(payload_str):
                        match_snippet = pattern.search(payload_str).group(0)
                        log_alert(
                            attack_name, 
                            src_ip, 
                            f"{dst_ip}:{dport if dport else 'N/A'}", 
                            f"Matched Signature Pattern: '{match_snippet}'", 
                            severity="CRITICAL"
                        )
        except Exception:
            pass

# ==============================================================================
# PACKET DISSECTOR & IDS ROUTER
# ==============================================================================
def packet_callback(pkt, payload_limit=48, save_list=None):
    if save_list is not None:
        save_list.append(pkt)

    timestamp = datetime.now().strftime("%H:%M:%S")

    # Layer 3 Processing
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

    sport, dport = None, None

    # Layer 4 Processing
    if TCP in pkt:
        stats["TCP"] += 1
        tcp = pkt[TCP]
        sport, dport = tcp.sport, tcp.dport
        tag = f"{Colors.BLUE}[TCP]{Colors.RESET}"
        print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {tag} {src_ip}:{Colors.YELLOW}{sport}{Colors.RESET} -> {dst_ip}:{Colors.YELLOW}{dport}{Colors.RESET} | ttl={ttl} len={length} flags={Colors.PURPLE}{tcp.flags}{Colors.RESET}")

    elif UDP in pkt:
        stats["UDP"] += 1
        udp = pkt[UDP]
        sport, dport = udp.sport, udp.dport
        tag = f"{Colors.CYAN}[UDP]{Colors.RESET}"
        print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {tag} {src_ip}:{Colors.YELLOW}{sport}{Colors.RESET} -> {dst_ip}:{Colors.YELLOW}{dport}{Colors.RESET} | ttl={ttl} len={length}")

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

    # Payload Display
    if Raw in pkt:
        payload_data = pkt[Raw].load
        clean_text = format_payload(payload_data, limit=payload_limit)
        print(f"      {Colors.PURPLE}└── [DATA]{Colors.RESET} {clean_text}")

    # PASS PACKET TO NIDS DETECTION ENGINE
    analyze_packet_for_threats(pkt, src_ip, dst_ip, sport, dport)

# ==============================================================================
# METRICS & THREAT SUMMARY DISPLAY
# ==============================================================================
def render_summary():
    elapsed = round(time.time() - start_timestamp, 2) if start_timestamp else 0
    total = sum(stats.values())
    total_alerts = sum(threat_stats.values())

    print("\n" + Colors.CYAN + "=" * 68 + Colors.RESET)
    print(f"{Colors.BOLD}{Colors.WHITE}                 SESSION TRAFFIC & THREAT AUDIT METRICS{Colors.RESET}")
    print(Colors.CYAN + "=" * 68 + Colors.RESET)
    print(f" {Colors.BOLD}Runtime Duration{Colors.RESET}    : {elapsed} seconds")
    print(f" {Colors.BOLD}Total Packets{Colors.RESET}       : {total}")
    print(f" {Colors.BOLD}Total Alerts Raised{Colors.RESET} : {Colors.RED}{total_alerts}{Colors.RESET}")
    print(Colors.CYAN + "-" * 68 + Colors.RESET)

    print(f"{Colors.BOLD} Protocol Distribution:{Colors.RESET}")
    for proto, count in stats.items():
        pct = (count / total * 100) if total > 0 else 0
        bar = "█" * int(pct // 5)
        print(f" • {proto:<6} : {count:<5} | {pct:>5.1f}% | {Colors.BLUE}{bar:<20}{Colors.RESET}")

    if threat_stats:
        print(Colors.CYAN + "-" * 68 + Colors.RESET)
        print(f"{Colors.BOLD}{Colors.RED} Detected Security Threats:{Colors.RESET}")
        for threat, count in threat_stats.items():
            print(f" • {threat:<32} : {Colors.RED}{count} Incident(s){Colors.RESET}")

    print(Colors.CYAN + "=" * 68 + Colors.RESET + "\n")

# ==============================================================================
# ENTRY POINT
# ==============================================================================
def main():
    global start_timestamp

    parser = argparse.ArgumentParser(
        description="NIDS Engine",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--interface", help="Target network adapter (e.g., eth0, Wi-Fi)", default=None)
    parser.add_argument("-c", "--count", type=int, help="Stop execution after N packets (default: continuous)", default=0)
    parser.add_argument("-f", "--filter", help="Kernel BPF filter rule (e.g., 'tcp', 'port 80')", default="")
    parser.add_argument("-w", "--write", help="Write frames to a PCAP dump", default=None)
    parser.add_argument("-l", "--limit", type=int, help="Payload preview cutoff limit (default: 48 bytes)", default=48)

    args = parser.parse_args()

    os.system('cls' if os.name == 'nt' else 'clear')
    print(BANNER)

    print(f"{Colors.BOLD}[*] NIDS Engine Initialization:{Colors.RESET}")
    print(f"    • Bound Interface : {Colors.YELLOW}{args.interface if args.interface else 'Default Adapter'}{Colors.RESET}")
    print(f"    • BPF Kernel Rule : {Colors.YELLOW}{args.filter if args.filter else 'None (Promiscuous All)'}{Colors.RESET}")
    print(f"    • Packet Quota    : {Colors.YELLOW}{str(args.count) if args.count > 0 else 'Unlimited (Ctrl+C to abort)'}{Colors.RESET}")
    print(f"    • Log File        : {Colors.CYAN}{LOG_FILE}{Colors.RESET}")
    if args.write:
        print(f"    • PCAP Target     : {Colors.CYAN}{args.write}{Colors.RESET}")
    print(f"\n{Colors.BLUE}[+] NIDS Rules Engine Active. Monitoring live traffic streams...{Colors.RESET}\n")

    pcap_buffer = [] if args.write else None
    start_timestamp = time.time()

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=lambda pkt: packet_callback(pkt, payload_limit=args.limit, save_list=pcap_buffer),
            count=args.count,
            store=bool(args.write),
            promisc=False
        )
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] NIDS session interrupted by operator.{Colors.RESET}")
    except PermissionError:
        print(f"\n{Colors.RED}[-] Critical: Socket access denied. Elevate terminal permissions (sudo / Admin).{Colors.RESET}")
        sys.exit(1)
    except Exception as err:
        print(f"\n{Colors.RED}[-] NIDS Runtime Failure: {err}{Colors.RESET}")
        sys.exit(1)
    finally:
        render_summary()
        if args.write and pcap_buffer:
            print(f"{Colors.CYAN}[*] Flushing buffer to PCAP file '{args.write}'...{Colors.RESET}")
            wrpcap(args.write, pcap_buffer)
            print(f"{Colors.CYAN}[+] Dump written successfully.{Colors.RESET}")

if __name__ == "__main__":
    try:
        main()
    finally:
        input("\nPress Enter to exit...")

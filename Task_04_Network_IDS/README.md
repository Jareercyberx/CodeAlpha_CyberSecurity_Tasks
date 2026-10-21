# Task 04: Network Intrusion Detection System (NIDS)

Developer: Cyber Jerry

## Overview
This is a custom Network Intrusion Detection System built with Python. It analyzes network traffic streams in real time to detect active attacks and logs security incidents.

## Features
- Detects port scanning activity based on unique port access thresholds
- Detects rate anomaly attacks like TCP SYN floods and ICMP floods
- Performs deep packet inspection for SQL Injection, XSS, Path Traversal, and Shell commands
- Automatically records security incident details into nids_alerts.log

## How to Run

On Windows:
python nids.py -i "Wi-Fi"

On Linux:
sudo python3 nids.py -i eth0

Check alerts log file:
Open nids_alerts.log in any text editor to view saved alerts.
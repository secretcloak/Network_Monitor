# Network_Monitor

Overview

This project implements a network monitoring system that continuously captures, filters, and replays packets using raw sockets. It demonstrates the use of custom stacks and queues to manage packet data and protocol parsing in real time.

Features

Continuous live packet capture from eth0.

Layer dissection for Ethernet, IPv4, IPv6, TCP, and UDP.

Filtering by source/destination IP.

Replay system with delay and retry (2 attempts).

Graceful stop with Ctrl+C.

Optional interactive commands (list, show <id>, exit).

Build Instructions
g++ -pthread network_monitor.cpp -o network_monitor


Root access is required for raw socket operations.

Run Instructions
sudo ./network_monitor eth0


The program will:

Capture packets for 60 seconds (default).

Display packet IDs, timestamps, IPs.

Dissect and filter continuously.

Replay filtered packets.

To Stop

Press Ctrl + C at any time to stop all threads safely.

Threads will exit gracefully, and resources will be released.

To Modify Filter

Edit these lines in main():

std::string demo_src = "192.168.1.10";
std::string demo_dst = "192.168.1.1";


Leave empty ("") to match any address.

Example Output
=== Current Packet List ===
ID: 5 | Time: 2025-10-23 14:30:18.123 | Src: 192.168.1.10 | Dst: 192.168.1.1 | Proto: TCP | Size: 1514

Dissected Layers (Packet ID: 5)
Ethernet -> IPv4 -> TCP

Error Handling

If replay fails, the packet is retried twice before being discarded.

Oversized packets (>1500 bytes) are skipped if they exceed the allowed threshold.

Notes

The program requires root privileges.

Works on Linux only (due to raw socket usage).

The capture interface can be changed by command line argument.

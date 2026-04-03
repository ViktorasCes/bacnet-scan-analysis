# BACnet PCAP Analysis

A Python script to analyse BACnet PCAP results and generate device hardware inventories. It parses network traffic to identify IP Controllers, BBMDs, Routers, and nested MS/TP sub-networks, outputting a streamlined device list.

## Features
* Uses Python's built-in `subprocess` module to interface directly with TShark.
* Extracts original IP addresses routed inside BBMD Forwarded-NPDUs.
* Associates Instance IDs with physical MAC/IP addresses and `I-Am` packets.
* Generates a clean, simplified CSV (`<pcap_name>_results.csv`) formatted for building automation auditing and analysis.
* Dynamically extracts the Site Identifier directly from the PCAP filename.

## Prerequisites
The script requires **TShark** (the command-line engine for Wireshark), version 4.0 or higher.

*Note: This script has been tested only on a Linux environment.*

* **Linux (Debian/Ubuntu):** `sudo apt-get install tshark`

## Installation & Environment Setup

While this script has no external Python dependencies, it is recommended to run it inside a virtual environment to maintain a clean workspace.

```bash
# 1. Clone the repository
git clone git@github.com:ViktorasCes/bacnet-scan-analysis.git
cd bacnet-scan-analysis

# 2. Create a Virtual Environment
python3 -m venv bacnet_env

# 3. Activate the Environment
source bacnet_env/bin/activate
```

## Usage

Run the script and pass the path to your `.pcap` file as the only argument:

```bash
python3 bacnet_scan_analysis.py path/to/your_capture.pcap
```

### Expected Console Output
The script will print a summary of the capture metadata and device counts:

```text
========================================
      BACnet Packet Capture Results
========================================
File:           us-pao-em15-mx1-1-01_2025-12-29_17-37-45.pcap
Duration:       0 hours 59 minutes (3598.47 seconds)
----------------------------------------
Total IP Endpoints:  119
Total MSTP Devices:  19
----------------------------------------
Total Entries Found: 138
========================================

[+] Successfully saved BACnet Packet Capture Results to: us-pao-em15-mx1-1-01_2025-12-29_17-37-45_results.csv
```

## CSV Output Columns

The CSV export has been streamlined to include only vital hardware and routing information. Below is a breakdown of what each column represents:

| Column Name | Description |
| :--- | :--- |
| **Site Identifier** | Dynamically extracted from the PCAP filename (e.g., `us-pao-em15`). |
| **Instance Number** | The Logical BACnet Device ID (extracted safely from `I-Am` packets). |
| **Network Address** | The physical location on the network (e.g., `100.67.24.91:47808` for IP endpoints or `Net: 32121/4` for MS/TP devices where the MAC is appended). |
| **Manufacturer** | The vendor name, translated directly from the official ASHRAE Vendor ID registry. |
| **Connection Type** | `ip` (direct Ethernet endpoint) or `mstp` (routed via a serial network). |
| **Routing Enabled** | `True` if the node announced a Source Network header, indicating it routes traffic to sub-networks. |
| **BBMD Enabled** | `True` if the node routed traffic via `bvlc.function 0x04` (Forwarded-NPDU), indicating it acts as a Broadcast Management Device. |
| **Last Detected** | The exact Wireshark packet capture date (`MM/DD/YY`) of the most recent packet sent by the device. |

## Versioning
* **v1.0.0:** Initial release. Includes TShark subprocess integration, BBMD resolution, hardware-anchored parsing, pure ASHRAE vendor mapping, duration formatting, and streamlined dynamic CSV generation.
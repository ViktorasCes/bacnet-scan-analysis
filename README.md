# BACnet PCAP Analysis

A Python script to analyse BACnet PCAP results and generate device hardware inventories. It parses network traffic to identify IP Controllers, BBMDs, Routers, and nested MS/TP sub-networks, outputting a streamlined device list.

## Features
* Uses Python's built-in `subprocess` module to interface directly with TShark.
* Extracts original IP addresses routed inside BBMD Forwarded-NPDUs.
* Associates Instance IDs securely with physical MAC/IP addresses via `I-Am` packet anchoring.
* Extracts true, on-the-wire BACnet object names dynamically.
* Generates a clean, simplified CSV (`<pcap_name>_results.csv`) formatted for building automation auditing and analysis.
* Dynamically extracts the Site Identifier directly from the PCAP filename.

## Prerequisites
The script requires **TShark** (the command-line engine for Wireshark), version 4.0 or higher.

*Note: This script has been tested only on a Linux environment.*

* **Linux (Debian/Ubuntu):** `sudo apt-get install tshark`

## Installation & Environment Setup

While this script has no external Python dependencies, it is recommended to run it inside a virtual environment to maintain a clean workspace.

~~~bash
# 1. Clone the repository
git clone git@github.com:ViktorasCes/bacnet-scan-analysis.git
cd bacnet-scan-analysis

# 2. Create a Virtual Environment
python3 -m venv bacnet_env

# 3. Activate the Environment
source bacnet_env/bin/activate
~~~

## Usage

Run the script and pass the path to your `.pcap` file as the only argument:

~~~bash
python3 bacnet_scan_analysis.py path/to/your_capture.pcap
~~~

### Expected Console Output
The script will print a summary of the capture metadata and device counts:

~~~text
========================================
      BACnet Packet Capture Results
========================================
File:           building-name-mx1-1-01_2025-12-29_17-37-45.pcap
Duration:       0 hours 59 minutes (3598.47 seconds)
----------------------------------------
Total IP Endpoints:  119
Total MSTP Devices:  19
----------------------------------------
Total Entries Found: 138
========================================

[+] Successfully saved BACnet Packet Capture Results to: building-name-mx1-1-01_2025-12-29_17-37-45_results.csv
~~~

## CSV Output Columns

The CSV export has been streamlined to include only vital hardware and routing information. Below is a breakdown of what each column represents:

| Column Name | Description |
| :--- | :--- |
| **Site Identifier** | Dynamically extracted from the PCAP filename (e.g., `building-name`). |
| **Instance Number** | The Logical BACnet Device ID (extracted safely from `I-Am` packets). |
| **Device Name** | The actual BACnet `objectName` broadcasted by the device. |
| **Network Address** | The physical location on the network (e.g., `100.67.24.91:47808` for IP endpoints or `Net: 32121/4` for MS/TP devices where the MAC is appended). |
| **Gateway IP** | For MS/TP devices, the IP address of the BACnet Router that encapsulated the sub-network traffic. Left blank for direct IP endpoints. |
| **Manufacturer** | The vendor name, translated directly from the official ASHRAE Vendor ID registry. |
| **Connection Type** | `ip` (direct Ethernet endpoint) or `mstp` (routed via a serial network). |
| **Routing Enabled** | `True` if the node announced a Source Network header, indicating it routes traffic to sub-networks. |
| **BBMD Enabled** | `True` if the node routed traffic via `bvlc.function 0x04` (Forwarded-NPDU), indicating it acts as a Broadcast Management Device. |
| **Last Detected** | The exact Wireshark packet capture date (`MM/DD/YY`) of the most recent packet sent by the device. |

## Versioning
* **v1.4.0 (Latest)**: Feature: Added extraction of the true `bacapp.object_name` directly from the traffic instead of synthesising a generic string. Feature: Added a `Gateway IP` column to easily identify which BACnet router is hosting each MS/TP network.
* **v1.3.0**: Bug Fix: Eliminated the "Duplicate Instance 1" bug by securely anchoring ID extractions strictly to `I-Am` broadcast messages, avoiding pollution from point polling. UX Fix: Filtered out pure client/scanner IP addresses to ensure the final inventory accurately reflects physical infrastructure.
* **v1.2.0**: Bug Fix: Repaired the VENDOR_REGISTRY using verified Wireshark dissector definitions (Vendor ID 24 is now correctly mapped to Automated Logic Corporation). UX Fix: Added file-existence validation to gracefully catch errors if a PCAP file path is incorrect.
* **v1.0.0:** Initial release. Includes TShark subprocess integration, BBMD resolution, ASHRAE vendor mapping, duration formatting, and output CSV generation.
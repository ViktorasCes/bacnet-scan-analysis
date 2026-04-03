# BACnet PCAP Analyser

A Python script designed to analyse BACnet PCAP files and generate hardware-anchored device inventories. It parses network traffic to identify IP Controllers, BBMDs, Routers, and nested MS/TP sub-networks, outputting a comprehensive device list.

## Features
* **No External Dependencies:** Uses Python's built-in `subprocess` module to interface directly with TShark.
* **Deep Packet Inspection:** Extracts original IP addresses routed inside BBMD Forwarded-NPDUs.
* **Hardware Anchoring:** Associates Instance IDs strictly with physical MAC/IP addresses and verified `I-Am` packets.
* **Standardised Output:** Generates a clean CSV (`<pcap_name>_results.csv`) formatted for building automation auditing and analysis.

## Prerequisites
The script requires **TShark** (the command-line engine for Wireshark), version 4.0 or higher. 

*Note: This script has been tested on Linux and macOS environments. Windows is currently unsupported.*

* **Linux (Debian/Ubuntu):** `sudo apt-get install tshark`
* **macOS:** Download the standard Wireshark installer from [wireshark.org](https://www.wireshark.org/) or install via Homebrew (`brew install wireshark`).

## Installation & Environment Setup

While this script has no external Python dependencies, it is recommended to run it inside a virtual environment to maintain a clean workspace.

```bash
# 1. Clone the repository
git clone [https://github.com/yourusername/bacnet-analyser.git](https://github.com/yourusername/bacnet-analyser.git)
cd bacnet-analyser

# 2. Create a Virtual Environment
python3 -m venv bacnet_env

# 3. Activate the Environment
source bacnet_env/bin/activate
```

## Usage

Run the script and pass the path to your `.pcap` or `.pcapng` file as the only argument:

```bash
python3 bacnet_scan_analysis.py path/to/your_capture.pcap
```

### Expected Console Output
The script will print a summary of the capture metadata and device counts:

```text
========================================
      BACnet Packet Capture Results
========================================
File:           building-name-capture_2025-12-29.pcap
Duration:       0 hours 59 minutes (3598.47 seconds)
----------------------------------------
Total IP Endpoints:  119
Total MSTP Devices:  19
----------------------------------------
Total Entries Found: 138
========================================

[+] Successfully saved BACnet Packet Capture Results to: building-name-capture_2025-12-29_results.csv
```

## CSV Output Columns

Below is a breakdown of what each column in the generated CSV represents:

| Column Name | Description |
| :--- | :--- |
| **Monitoring Node Name** | Static field for site or building identification. |
| **Device ID** | The Logical BACnet Instance Number (extracted safely from `I-Am` packets). |
| **Address** | The physical location on the network (e.g., `100.67.24.91:47808` for IP endpoints or `Net: 32121/4` for MS/TP devices). |
| **MAC Address** | Left blank (MS/TP MAC addresses are bundled directly into the Address column per convention). |
| **Device Name** | Left blank pending future APDU text parsing enhancements. |
| **Device Alias** | Left blank for manual entry by auditors. |
| **Vendor Name** | The manufacturer name, translated directly from the official ASHRAE Vendor ID registry. |
| **Device Type** | `ip` (direct ethernet endpoint) or `mstp` (routed via a serial network). |
| **Is BACnet Router** | `True` if the node announced a Source Network header, indicating it routes traffic to sub-networks. |
| **Is BBMD** | `True` if the node routed traffic via `bvlc.function 0x04` (Forwarded-NPDU), indicating it acts as a Broadcast Management Device. |
| **Last Seen** | The exact Wireshark packet capture date (`MM/DD/YY`) of the most recent packet sent by the device. |

## Versioning
* **v1.0.0:** Initial release. Includes TShark subprocess integration, BBMD resolution, hardware-anchored parsing, pure ASHRAE vendor mapping, duration formatting, and dynamic CSV generation.
import subprocess
import csv
import sys
import os
import re
from datetime import datetime

# Verified ASHRAE Vendor IDs
VENDOR_REGISTRY = {
    "0": "ASHRAE",
    "1": "NIST",
    "2": "The Trane Company",
    "3": "McQuay International",
    "4": "PolarSoft",
    "5": "Johnson Controls, Inc.",
    "6": "American Auto-Matrix",
    "7": "Siemens Schweiz AG",
    "8": "Delta Controls",
    "9": "Siemens Schweiz AG",
    "10": "Schneider Electric",
    "17": "Honeywell Inc.",
    "18": "Alerton / Honeywell",
    "19": "TAC AB",
    "20": "Hewlett-Packard Company",
    "21": "Dorsette's Inc.",
    "22": "Siemens Schweiz AG",
    "23": "York Controls Group",
    "24": "Automated Logic Corporation",
    "25": "CSI Control Systems International",
    "26": "Phoenix Controls Corporation",
    "112": "Distech Controls",
    "190": "Danfoss Drives A/S"
}

def get_pcap_info(pcap_file):
    """Uses Wireshark's capinfos utility to extract file metadata."""
    info = {'duration': 'Unknown'}
    try:
        cmd = ["capinfos", "-u", pcap_file]
        res = subprocess.run(cmd, capture_output=True, text=True)
        for line in res.stdout.split('\n'):
            if "Capture duration:" in line:
                raw_duration = line.split("duration:")[1].strip()
                match = re.search(r"([\d\.]+)", raw_duration)
                if match:
                    seconds_total = float(match.group(1))
                    hours = int(seconds_total // 3600)
                    minutes = int((seconds_total % 3600) // 60)
                    info['duration'] = f"{hours} hours {minutes} minutes ({seconds_total:.2f} seconds)"
                else:
                    info['duration'] = raw_duration
    except Exception:
        pass
    return info

def analyse_pcap(pcap_file):
    print(f"Analysing {os.path.basename(pcap_file)}... Please wait.")
    
    cmd = [
        "tshark", "-r", pcap_file,
        "-T", "fields",
        "-e", "ip.src",                     
        "-e", "udp.srcport",                
        "-e", "bvlc.function",              
        "-e", "bvlc.fwd_ip",                
        "-e", "bacnet.snet",                
        "-e", "bacnet.sadr_mstp",           
        "-e", "bacapp.instance_number",     
        "-e", "bacapp.vendor_identifier",
        "-e", "bacapp.unconfirmed_service", 
        "-e", "bacapp.object_name",         # Extracting actual BACnet object name
        "-e", "frame.time_epoch",           
        "-E", "separator=|"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("\n[!] TShark encountered an error:")
        print(result.stderr)
        sys.exit(1)
        
    ip_metadata = {}  
    devices = {}      
    
    for line in result.stdout.strip().split('\n'):
        if not line: continue
        
        # Padded to 11 fields to include object_name
        parts = (line + "|||||||||||").split('|')[:11]
        ip_src, udp_port, bvlc_func, fwd_ip, snet, sadr, instance, vendor, unconf_svc, obj_name, frame_time = [p.strip() for p in parts]
        
        ip_src = ip_src.split(',')[0]
        if not ip_src: continue 
            
        udp_port = udp_port.split(',')[0] if udp_port else "47808"
        sender_addr = f"{ip_src}:{udp_port}"
        
        try:
            timestamp = float(frame_time.split(',')[0]) if frame_time else datetime.now().timestamp()
        except ValueError:
            timestamp = datetime.now().timestamp()
        
        if sender_addr not in ip_metadata:
            ip_metadata[sender_addr] = {'is_router': False, 'is_bbmd': False, 'last_seen': timestamp}
        else:
            ip_metadata[sender_addr]['last_seen'] = max(ip_metadata[sender_addr]['last_seen'], timestamp)
            
        real_addr = sender_addr
        if bvlc_func in ['4', '0x04', '0x0004']:
            ip_metadata[sender_addr]['is_bbmd'] = True 
            real_ip = fwd_ip.split(',')[0] if fwd_ip else ""
            if real_ip:
                real_addr = f"{real_ip}:47808"
                if real_addr not in ip_metadata:
                    ip_metadata[real_addr] = {'is_router': False, 'is_bbmd': False, 'last_seen': timestamp}
                else:
                    ip_metadata[real_addr]['last_seen'] = max(ip_metadata[real_addr]['last_seen'], timestamp)
        
        snet_val = snet.split(',')[0] if snet else ""
        sadr_val = sadr.split(',')[0] if sadr else ""
        
        if snet_val:
            ip_metadata[real_addr]['is_router'] = True
            
        if snet_val and sadr_val:
            device_key = f"MSTP|{snet_val}|{sadr_val}"
            dev_type = "mstp"
            dev_address = f"{snet_val}/{sadr_val}"
            gateway_ip = real_addr  # Store the routing IP encapsulating this MS/TP packet
        else:
            device_key = f"IP|{real_addr}"
            dev_type = "ip"
            dev_address = real_addr
            gateway_ip = ""

        if device_key not in devices:
            devices[device_key] = {
                'type': dev_type,
                'address': dev_address,
                'gateway_ip': gateway_ip,
                'device_id': "",
                'device_name': "",
                'vendor_id': "",
                'last_seen': timestamp
            }
        else:
            devices[device_key]['last_seen'] = max(devices[device_key]['last_seen'], timestamp)
            # Ensure gateway IP is updated if discovered later
            if not devices[device_key]['gateway_ip'] and gateway_ip:
                devices[device_key]['gateway_ip'] = gateway_ip
                
        # Continually capture the object name if present in any packet related to this device
        if obj_name:
            extracted_name = obj_name.split(',')[0].strip()
            if extracted_name and not devices[device_key]['device_name']:
                devices[device_key]['device_name'] = extracted_name
            
        # Extract Device ID via strictly verified I-Am broadcasts
        if '0' in unconf_svc.split(','):
            if instance:
                inst = instance.split(',')[0].strip()
                if inst:
                    devices[device_key]['device_id'] = inst
            if vendor:
                v_id = vendor.split(',')[0].strip()
                if v_id:
                    devices[device_key]['vendor_id'] = v_id

    return devices, ip_metadata

def generate_csv(pcap_file):
    if not os.path.isfile(pcap_file):
        print(f"\n[!] Error: The file '{pcap_file}' was not found.")
        print("Please check the path and try again.\n")
        sys.exit(1)
        
    devices, ip_metadata = analyse_pcap(pcap_file)
    pcap_info = get_pcap_info(pcap_file)
    
    # Pre-process final list to eliminate purely client IPs (Scanners/Workstations)
    final_devices = []
    for dev_key, d in devices.items():
        is_ip = (d['type'] == 'ip')
        address = d['address']
        router_flag = ip_metadata.get(address, {}).get('is_router', False)
        bbmd_flag = ip_metadata.get(address, {}).get('is_bbmd', False)
        
        # If an IP has no Device ID, is not routing, and is not a BBMD, it's a client. Drop it.
        if is_ip and not d['device_id'] and not router_flag and not bbmd_flag:
            continue
            
        final_devices.append((dev_key, d))
        
    num_ip = sum(1 for _, d in final_devices if d['type'] == 'ip')
    num_mstp = sum(1 for _, d in final_devices if d['type'] == 'mstp')
    
    print("\n" + "="*40)
    print("      BACnet Packet Capture Results")
    print("="*40)
    print(f"File:           {os.path.basename(pcap_file)}")
    print(f"Duration:       {pcap_info['duration']}")
    print("-" * 40)
    print(f"Total IP Endpoints:  {num_ip}")
    print(f"Total MSTP Devices:  {num_mstp}")
    print("-" * 40)
    print(f"Total Entries Found: {num_ip + num_mstp}")
    print("="*40 + "\n")
    
    base_name = os.path.splitext(os.path.basename(pcap_file))[0]
    csv_file = f"{base_name}_results.csv"
    
    name_parts = base_name.split('-')
    site_id = "-".join(name_parts[:3]) if len(name_parts) >= 3 else name_parts[0]
    
    headers = [
        "Site Identifier", "Instance Number", "Device Name", "Network Address", 
        "Gateway IP", "Manufacturer", "Connection Type", "Routing Enabled", 
        "BBMD Enabled", "Last Detected"
    ]
    
    written_addresses = set()
    
    with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        # 1. Write Identified Hardware
        for dev_key, d in sorted(final_devices, key=lambda x: int(x[1]['device_id']) if x[1]['device_id'].isdigit() else 0):
            if not d['device_id']:
                continue 
                
            address = d['address']
            v_name = VENDOR_REGISTRY.get(d['vendor_id'], f"Vendor ID: {d['vendor_id']}") if d['vendor_id'] else ""
            
            router_flag = str(ip_metadata.get(address, {}).get('is_router', False)) if d['type'] == 'ip' else "False"
            bbmd_flag = str(ip_metadata.get(address, {}).get('is_bbmd', False)) if d['type'] == 'ip' else "False"
            last_seen_date = datetime.fromtimestamp(d['last_seen']).strftime("%m/%d/%y")
            
            writer.writerow([
                site_id, d['device_id'], d['device_name'], address, d['gateway_ip'], v_name, 
                d['type'], router_flag, bbmd_flag, last_seen_date
            ])
            written_addresses.add(address)
                
        # 2. Write Ghost Infrastructure (Routers/BBMDs without IDs)
        for dev_key, d in final_devices:
            if not d['device_id'] and d['address'] not in written_addresses:
                address = d['address']
                
                router_flag = str(ip_metadata.get(address, {}).get('is_router', False)) if d['type'] == 'ip' else "False"
                bbmd_flag = str(ip_metadata.get(address, {}).get('is_bbmd', False)) if d['type'] == 'ip' else "False"
                
                t_stamp = ip_metadata.get(address, {}).get('last_seen', d['last_seen'])
                last_seen_date = datetime.fromtimestamp(t_stamp).strftime("%m/%d/%y")
                
                writer.writerow([
                    site_id, "", d['device_name'], address, d['gateway_ip'], "", d['type'], 
                    router_flag, bbmd_flag, last_seen_date
                ])
                written_addresses.add(address)
                
    print(f"[+] Successfully saved BACnet Packet Capture Results to: {csv_file}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 bacnet_scan_analysis.py <your_file.pcap>")
        sys.exit(1)
        
    generate_csv(sys.argv[1])
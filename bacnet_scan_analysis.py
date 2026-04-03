import subprocess
import csv
import sys
import os
import re
from datetime import datetime

# Official ASHRAE Vendor IDs
VENDOR_REGISTRY = {
    "5": "Johnson Controls, Inc.",
    "8": "Delta Controls",
    "11": "Trane",
    "12": "Andover Controls",
    "14": "Honeywell",
    "17": "Alerton",
    "18": "Automated Logic Corporation",
    "20": "KMC Controls",
    "23": "Reliable Controls",
    "24": "Siemens Industry", 
    "112": "Distech Controls"
}

def get_pcap_info(pcap_file):
    """Uses Wireshark's capinfos utility to extract file metadata."""
    info = {'duration': 'Unknown'}
    try:
        # -u flag extracts the duration
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
    print("Extracting full packet data and timestamps... Please wait.")
    
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
        "-e", "frame.time_epoch",           
        "-E", "separator=|"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    ip_metadata = {}  
    devices = {}      
    
    for line in result.stdout.strip().split('\n'):
        if not line: continue
        
        parts = (line + "|||||||||").split('|')[:9]
        ip_src, udp_port, bvlc_func, fwd_ip, snet, sadr, instance, vendor, frame_time = [p.strip() for p in parts]
        
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
        else:
            device_key = f"IP|{real_addr}"
            dev_type = "ip"
            dev_address = real_addr

        if device_key not in devices:
            devices[device_key] = {
                'type': dev_type,
                'address': dev_address,
                'device_id': "",
                'vendor_id': "",
                'last_seen': timestamp
            }
        else:
            devices[device_key]['last_seen'] = max(devices[device_key]['last_seen'], timestamp)
            
        if instance:
            inst = instance.split(',')[0].strip()
            if inst and not devices[device_key]['device_id']:
                devices[device_key]['device_id'] = inst
                
        if vendor:
            v_id = vendor.split(',')[0].strip()
            if v_id and not devices[device_key]['vendor_id']:
                devices[device_key]['vendor_id'] = v_id

    return devices, ip_metadata

def generate_csv(pcap_file):
    devices, ip_metadata = analyse_pcap(pcap_file)
    pcap_info = get_pcap_info(pcap_file)
    
    num_ip = sum(1 for d in devices.values() if d['type'] == 'ip')
    num_mstp = sum(1 for d in devices.values() if d['type'] == 'mstp')
    
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
    
    headers = [
        "Monitoring Node Name", "Device ID", "Address", "MAC Address",
        "Device Name", "Device Alias", "Vendor Name", "Device Type",
        "Is BACnet Router", "Is BBMD", "Last Seen"
    ]
    
    written_addresses = set()
    
    with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for dev_key in sorted(devices.keys(), key=lambda x: int(devices[x]['device_id']) if devices[x]['device_id'].isdigit() else 0):
            d = devices[dev_key]
            if not d['device_id']:
                continue 
                
            is_ip = (d['type'] == 'ip')
            address = d['address']
            
            v_name = ""
            if d['vendor_id']:
                v_name = VENDOR_REGISTRY.get(d['vendor_id'], f"Vendor ID: {d['vendor_id']}")
                
            router_flag = str(ip_metadata.get(address, {}).get('is_router', False)) if is_ip else "False"
            bbmd_flag = str(ip_metadata.get(address, {}).get('is_bbmd', False)) if is_ip else "False"
            last_seen_date = datetime.fromtimestamp(d['last_seen']).strftime("%m/%d/%y")
            
            writer.writerow([
                "us-pao-em15", d['device_id'], address, "", "", "", v_name, 
                d['type'], router_flag, bbmd_flag, last_seen_date
            ])
            written_addresses.add(address)
                
        for dev_key, d in devices.items():
            if not d['device_id'] and d['address'] not in written_addresses:
                is_ip = (d['type'] == 'ip')
                address = d['address']
                
                router_flag = str(ip_metadata.get(address, {}).get('is_router', False)) if is_ip else "False"
                bbmd_flag = str(ip_metadata.get(address, {}).get('is_bbmd', False)) if is_ip else "False"
                
                t_stamp = ip_metadata.get(address, {}).get('last_seen', d['last_seen'])
                last_seen_date = datetime.fromtimestamp(t_stamp).strftime("%m/%d/%y")
                
                writer.writerow([
                    "us-pao-em15", "", address, "", "", "", "", d['type'], 
                    router_flag, bbmd_flag, last_seen_date
                ])
                written_addresses.add(address)
                
    print(f"[+] Successfully saved BACnet Packet Capture Results to: {csv_file}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 bacnet_scan_analysis.py <your_file.pcap>")
        sys.exit(1)
        
    generate_csv(sys.argv[1])
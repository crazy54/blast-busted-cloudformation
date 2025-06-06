# RVTools Synthetic Data Generator
#
# IMPORTANT NOTE: This script has been observed to time out in certain
# restricted Python execution environments when processing a large number of files
# or with very complex inter-dependencies. It is provided as a blueprint
# for local execution where such timeouts are less likely. For sandboxed
# environments, consider reducing num_rows_per_csv, the number of CSVs generated,
# or simplifying the column_strategies if timeouts occur.

import random
import string
import csv
import uuid
import zipfile
import os
import inspect # Intentionally re-included as part of the blueprint design
import argparse # Part A: Import argparse

# --- Output Directory Variables ---
BASE_OUTPUT_DIR = "RV_TOOL_OUTPUTS"
CSV_OUTPUT_DIR = os.path.join(BASE_OUTPUT_DIR, "CSVs")
ZIP_OUTPUT_DIR = os.path.join(BASE_OUTPUT_DIR, "ZIPs")

# --- Full CSV Headers ---
CSV_HEADERS = {
    "RVTools_tabvInfo.csv": ["VM ID", "DNS Name", "Connection State", "VMware Tools", "IP Address", "OS According to the VMware Tools", "OS According to the configuration file", "Powerstate", "CPU", "Memory", "NICs", "Disks", "Network #1", "Network #2", "Network #3", "Network #4", "VM Folder", "Resource Pool", "vCenter", "Datacenter", "Cluster", "ESX Host", "ESX Host Hw Model", "ESX Host Hw Vendor", "ESX Version", "ESX Build", "ESX Hw Uptime (sec)", "ESX Hw Uptime (days)", "ESX Hw Uptime (date)", "VM Overall CPU Usage (%)", "VM Overall CPU Usage (MHz)", "VM Overall Memory Usage (MB)", "VM Overall Memory Usage (%)", "VM Consumed Host Memory (MB)", "VM Guest Memory Usage (%)", "VM Ballooned Memory (MB)", "VM Swapped Memory (MB)", "VM Compressed Memory (MB)", "VM Uptime (sec)", "VM Uptime (days)", "VM Uptime (date)", "VMotion enabled", "Template", "Tags", "Logdirectory", "VM UUID", "Instance UUID", "Config Issue", "Change Tracking", "Virtual HW Version", "Virtual HW Upgrade Status", "Virtual HW Upgrade Policy", "HA Protected", "FT Status", "FT Latency Status", "FT Bandwidth Status", "FT Secondary Latency", "Provisioned MB", "In Use MB", "Unshared MB", "HA RestartPriority", "HA IsolationResponse", "HA VM Monitoring", "Cluster rule(s)", "Cluster rule name(s)", "Boot Required", "Boot Delay", "Boot Retry Delay", "Boot Retry Enabled", "Boot BIOS Setup", "Firmware", "HW version", "VM Create Date", "VM Create User", "VM Delete Date", "VM Delete User", "Num vCPU", "Num CoresPerSocket", "Memory Reservation", "CPU Reservation", "CPU Limit", "Memory Limit", "OverallCpuUsage", "GuestMemUsage", "HostMemUsage", "BalloonedMem", "SwappedMem", "CompressedMem", "UptimeSeconds", "CreateDate", "ChangeVersion", "CpuidLimit", "CpuidMask", "VFlashCacheReservation", "MemoryOverhead", "ToolsInstallerMounted", "Annotations", "CustomAttributes", "VI SDK Server", "VI SDK API Version", "VI SDK Server Type"],
    "RVTools_tabvHealth.csv": [ "VM ID", "DNS Name", "Message", "Status", "vCenter", "Datacenter", "Cluster", "ESX Host", "Object type", "Object Name"],
    "RVTools_tabvDisk.csv": ["VM ID", "DNS Name", "Capacity MB", "Capacity GB", "Used MB", "Used GB", "Free MB", "Free GB", "Free %", "Powerstate", "Disk", "Thin", "Persistence", "Disk Mode", "Controller", "Unit", "Path", "vmdk Path", "Raw or RDM?", "SCSI Canonical Name", "Device Name", "Disk Shares", "Disk IOPS Limit", "Disk UUID", "Disk Key", "Filename", "Sorting", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvPartition.csv": ["VM ID", "DNS Name", "Disk", "Partition", "Capacity MB", "Capacity GB", "Consumed MB", "Consumed GB", "Free MB", "Free GB", "Free %", "Powerstate", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvNetwork.csv": ["VM ID", "DNS Name", "Network adapter", "Connected", "Connect at power on", "MAC Address", "IP Address", "Subnet mask", "Gateway", "Port Group Key", "Port Group", "Switch Name", "Switch Type", "VLAN ID", "Powerstate", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvFloppy.csv": ["VM ID", "DNS Name", "Floppy drive", "Connected", "Connect at power on", "Filename", "Powerstate", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvCD.csv": ["VM ID", "DNS Name", "CD/DVD Drive", "Connected", "Connect at power on", "Device Type", "Filename", "Powerstate", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvUSB.csv": ["VM ID", "DNS Name", "USB Controller", "Family", "Speed", "EHCI Enabled", "Powerstate", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvSerial.csv": ["VM ID", "DNS Name", "Serial Port", "Connected", "Connect at power on", "Device Type", "Filename", "Powerstate", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvParallel.csv": ["VM ID", "DNS Name", "Parallel Port", "Connected", "Connect at power on", "Filename", "Powerstate", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvSnapshot.csv": ["VM ID", "DNS Name", "Snapshot Name", "Description", "Created", "User", "Size MB", "Size GB", "Is Current?", "Is Reverted?", "Powerstate", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvTools.csv": ["VM ID", "DNS Name", "VMware Tools Version", "VMware Tools Status", "Powerstate", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvHost.csv": ["ESX Host", "Cluster", "Datacenter", "vCenter", "CPUMhz", "NumCpu", "NumCpuCores", "NumCpuThreads", "CpuUsage %", "CpuUsage MHz", "Mem Capacity MB", "Mem Capacity GB", "Mem Usage MB", "Mem Usage GB", "Memory Usage %", "Network (Mbit/s)", "Disk (KB/s)", "Vendor", "Model", "BIOS Version", "Service Tag", "OS Version", "Build", "Stateless", "Boot Order", "Boot Time", "Custom Fields"],
    "RVTools_tabvHBA.csv": ["ESX Host", "Device", "Driver", "Model", "WWNN", "WWPN", "Speed", "Status", "vCenter", "Datacenter", "Cluster"],
    "RVTools_tabvNIC.csv": ["ESX Host", "Device", "Driver", "Speed", "Duplex", "MAC Address", "IP Address", "Subnet Mask", "Gateway", "MTU", "Observed IP Ranges", "WakeOnLAN", "vSwitch", "Port Group", "Virtual NICs", "vCenter", "Datacenter", "Cluster"],
    "RVTools_tabvSwitch.csv": ["ESX Host", "Switch Name", "Type", "Num Ports", "Free Ports", "Uplinks", "Promiscuous Mode", "MAC Address Changes", "Forged Transmits", "Traffic Shaping", "Beacon Interval", "Notify Switches", "Rolling Order", "Check Beacon", "vCenter", "Datacenter", "Cluster"],
    "RVTools_tabvPort.csv": ["ESX Host", "Port Group", "vSwitch", "VLAN ID", "Active Clients", "Promiscuous Mode", "MAC Address Changes", "Forged Transmits", "Traffic Shaping", "vCenter", "Datacenter", "Cluster"],
    "RVTools_tabvDVPort.csv": ["ESX Host", "DVPortgroup Name", "DVSwitch Name", "Port ID", "VLAN ID", "Connected Object", "Object Type", "Status", "vCenter", "Datacenter", "Cluster"],
    "RVTools_tabvDVSwitch.csv": ["ESX Host", "DVSwitch Name", "Version", "Num Ports", "Contact", "Description", "Max MTU", "Beacon Interval", "Beacon Threshold", "IO Control Enabled", "Network Resource Pools", "vCenter", "Datacenter", "Cluster"],
    "RVTools_tabvDatastore.csv": ["ESX Host", "Datastore", "Type", "Capacity MB", "Capacity GB", "Free MB", "Free GB", "Free %", "Provisioned MB", "Provisioned GB", "InUse MB", "InUse GB", "Shared", "SSD", "Local", "VMFS Version", "Block Size", "Num VMs", "Num vDisks", "SIOC Enabled", "SIOC Congestion Threshold", "vCenter", "Datacenter", "Cluster"],
    "RVTools_tabvLicense.csv": ["vCenter", "Product Name", "License Key", "Expiration Date", "Licensed To", "Features"],
    "RVTools_tabvFile.csv": ["VM ID", "DNS Name", "Filename", "Filesize", "Last Modified", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvVMOnSan.csv": ["VM ID", "DNS Name", "Datastore", "LUN ID", "vCenter", "Datacenter", "Cluster", "ESX Host"],
    "RVTools_tabvSanLun.csv": ["ESX Host", "LUN ID", "Device Name", "Canonical Name", "Vendor", "Model", "Capacity GB", "Block Size", "Multipath Policy", "vCenter", "Datacenter", "Cluster"],
    "RVTools_tabvSanPath.csv": ["ESX Host", "LUN ID", "Path ID", "State", "Adapter", "Target", "vCenter", "Datacenter", "Cluster"],
    "RVTools_tabvMultipath.csv": ["ESX Host", "LUN ID", "Policy", "Preferred Path", "Active Path", "Paths", "vCenter", "Datacenter", "Cluster"]
}

CSV_GENERATION_ORDER = [
    "RVTools_tabvHost.csv", "RVTools_tabvInfo.csv", "RVTools_tabvNetwork.csv", "RVTools_tabvDisk.csv",
    "RVTools_tabvPartition.csv", "RVTools_tabvTools.csv", "RVTools_tabvSnapshot.csv", "RVTools_tabvHealth.csv",
    "RVTools_tabvFloppy.csv", "RVTools_tabvCD.csv", "RVTools_tabvUSB.csv", "RVTools_tabvSerial.csv",
    "RVTools_tabvParallel.csv", "RVTools_tabvDatastore.csv", "RVTools_tabvSwitch.csv", "RVTools_tabvPort.csv",
    "RVTools_tabvDVPort.csv", "RVTools_tabvDVSwitch.csv", "RVTools_tabvHBA.csv", "RVTools_tabvNIC.csv",
    "RVTools_tabvVMOnSan.csv", "RVTools_tabvSanLun.csv", "RVTools_tabvSanPath.csv", "RVTools_tabvMultipath.csv",
    "RVTools_tabvLicense.csv", "RVTools_tabvFile.csv"
]
for key in CSV_HEADERS.keys():
    if key not in CSV_GENERATION_ORDER: CSV_GENERATION_ORDER.append(key)

SHARED_CONTEXT = {
    'dcs': {}, 'clusters': {}, 'hosts': {}, 'vms': {}, 'datastores': {}, 'networks': {},
    'os_names': list(set(["Microsoft Windows Server 2019 (64-bit)", "Microsoft Windows Server 2022 (64-bit)", "Ubuntu Linux (64-bit)", "Red Hat Enterprise Linux 8 (64-bit)", "VMware ESXi 7.0", "CentOS 7 (64-bit)", "Debian GNU/Linux 11 (64-bit)"])),
}
REUSE_PROBABILITY = 0.6
MAX_NAME_GEN_ATTEMPTS = 50
DEBUG_ENTITY_GENERATION = False

def generate_random_string(length=10, current_row_context=None, **kwargs):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(length)) if length > 0 else ""

def generate_random_integer(min_val=0, max_val=100, current_row_context=None, **kwargs):
    return random.randint(min_val, max_val)

def generate_datetime_string(current_row_context=None, **kwargs):
    year, month, day = random.randint(2020, 2024), random.randint(1, 12), random.randint(1, 28)
    hour, minute, second = random.randint(0, 23), random.randint(0, 59), random.randint(0, 59)
    return f"{year}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"

def generate_boolean_string(true_val="True", false_val="False", current_row_context=None, **kwargs):
    return random.choice([true_val, false_val])

def generate_mac_address(current_row_context=None, **kwargs):
    return ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)]).upper()

def generate_ip_address(current_row_context=None, **kwargs):
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

def generate_os_name(current_row_context=None, **kwargs):
    return random.choice(SHARED_CONTEXT['os_names'])

def generate_tools_status(current_row_context=None, **kwargs):
    return random.choice(["guestToolsRunning", "guestToolsNotRunning", "toolsOk", "toolsOld", "toolsNotInstalled", "guestToolsCurrent"])

def generate_power_state(current_row_context=None, **kwargs):
    return random.choice(["poweredOn", "poweredOff", "suspended"])

def generate_generic_status(options=None, current_row_context=None, **kwargs):
    return random.choice(options if options else ['green', 'yellow', 'red', 'unknown', 'ok'])

def generate_ai_data(prompt="Generic AI prompt", current_row_context=None, **kwargs):
    return f"AI_DATA_FOR[{prompt.replace(' ', '_').upper()}]"

def _ensure_unique_name(name_prefix, collection_dict, max_val, attempts_limit, suffix_format="{:02d}", suffix_chaos=False):
    attempts = 0; name_to_use = f"{name_prefix}{suffix_format.format(random.randint(1, max_val))}"
    if suffix_chaos: name_to_use = f"{name_prefix}{random.choice(string.ascii_lowercase)}-{random.randint(1, max_val)}"
    while name_to_use in collection_dict and attempts < attempts_limit:
        if suffix_chaos: name_to_use = f"{name_prefix}{random.choice(string.ascii_lowercase)}-{random.randint(1, max_val)}"
        else: name_to_use = f"{name_prefix}{suffix_format.format(random.randint(1, max_val))}"
        attempts += 1
    if attempts >= attempts_limit and name_to_use in collection_dict:
        name_to_use = f"{name_to_use}-{uuid.uuid4().hex[:4]}";
        if DEBUG_ENTITY_GENERATION: print(f"Warning: Max attempts for {name_prefix}. Forced unique: {name_to_use}")
    return name_to_use

def generate_datacenter_entity(current_row_context=None, is_primary_identifier=False, force_new=False, **kwargs):
    if not force_new and not is_primary_identifier and SHARED_CONTEXT['dcs'] and random.random() < REUSE_PROBABILITY: return random.choice(list(SHARED_CONTEXT['dcs'].values()))
    name = _ensure_unique_name(f"DC-", SHARED_CONTEXT['dcs'], 5, MAX_NAME_GEN_ATTEMPTS, random.choice(['Main', 'DR', 'Dev', 'Test']) + "-{}", suffix_chaos=True)
    entity = {"id": f"dc-{uuid.uuid4().hex[:8]}", "name": name}; SHARED_CONTEXT['dcs'][name] = entity
    return entity

def generate_cluster_entity(current_row_context=None, is_primary_identifier=False, force_new=False, **kwargs):
    dc_entity = current_row_context.get('current_dc_entity')
    if not dc_entity: dc_entity = generate_datacenter_entity(is_primary_identifier=False, force_new=not SHARED_CONTEXT['dcs'])
    if not force_new and not is_primary_identifier and SHARED_CONTEXT['clusters'] and random.random() < REUSE_PROBABILITY:
        possible_clusters = [c for c in SHARED_CONTEXT['clusters'].values() if c['dc_name'] == dc_entity['name']]
        if possible_clusters: return random.choice(possible_clusters)
        if SHARED_CONTEXT['clusters']: return random.choice(list(SHARED_CONTEXT['clusters'].values()))
    name = _ensure_unique_name(f"Cluster-{string.ascii_uppercase[random.randint(0,5)]}", SHARED_CONTEXT['clusters'], 10, MAX_NAME_GEN_ATTEMPTS)
    entity = {"id": f"cluster-{uuid.uuid4().hex[:8]}", "name": name, "dc_name": dc_entity['name']}; SHARED_CONTEXT['clusters'][name] = entity
    return entity

def generate_host_entity(current_row_context=None, is_primary_identifier=False, force_new=False, **kwargs):
    cluster_entity = current_row_context.get('current_cluster_entity')
    if not cluster_entity: cluster_entity = generate_cluster_entity(is_primary_identifier=False, force_new=not SHARED_CONTEXT['clusters'], current_row_context=current_row_context)
    if not force_new and not is_primary_identifier and SHARED_CONTEXT['hosts'] and random.random() < REUSE_PROBABILITY:
        possible_hosts = [h for h in SHARED_CONTEXT['hosts'].values() if h['cluster_name'] == cluster_entity['name']]
        if possible_hosts: return random.choice(possible_hosts)
        if SHARED_CONTEXT['hosts']: return random.choice(list(SHARED_CONTEXT['hosts'].values()))
    name = _ensure_unique_name(f"esxi", SHARED_CONTEXT['hosts'], 50, MAX_NAME_GEN_ATTEMPTS, suffix_format="{:02d}.corp.local")
    entity = {"id": f"host-{uuid.uuid4().hex[:8]}", "name": name, "ip": generate_ip_address(), "cluster_name": cluster_entity['name'], "dc_name": cluster_entity['dc_name']}
    SHARED_CONTEXT['hosts'][name] = entity
    return entity

def generate_vm_entity(current_row_context=None, is_primary_identifier=False, force_new=False, **kwargs):
    host_entity = current_row_context.get('current_host_entity')
    if not host_entity: host_entity = generate_host_entity(is_primary_identifier=False, force_new=not SHARED_CONTEXT['hosts'], current_row_context=current_row_context)
    if not force_new and not is_primary_identifier and SHARED_CONTEXT['vms'] and random.random() < REUSE_PROBABILITY:
        possible_vms = [v for v in SHARED_CONTEXT['vms'].values() if v['host_name'] == host_entity['name']]
        if possible_vms: return random.choice(possible_vms)
        if SHARED_CONTEXT['vms']: return random.choice(list(SHARED_CONTEXT['vms'].values()))
    name_prefix = f"{random.choice(['prod', 'dev', 'test', 'uat', 'lab'])}-{random.choice(['web', 'app', 'db', 'util', 'mgmt'])}-"
    name = _ensure_unique_name(name_prefix, SHARED_CONTEXT['vms'], 99, MAX_NAME_GEN_ATTEMPTS)
    entity = {"id": f"vm-{uuid.uuid4().hex[:12]}", "name": name, "ip": generate_ip_address(), "mac": generate_mac_address(), "host_name": host_entity['name'], "powerstate": generate_power_state(), "os": generate_os_name(), "cluster_name": host_entity['cluster_name'], "dc_name": host_entity['dc_name']}
    SHARED_CONTEXT['vms'][name] = entity
    return entity

def generate_datastore_entity(current_row_context=None, is_primary_identifier=False, force_new=False, **kwargs):
    if not force_new and not is_primary_identifier and SHARED_CONTEXT['datastores'] and random.random() < REUSE_PROBABILITY: return random.choice(list(SHARED_CONTEXT['datastores'].values()))
    name_prefix = f"ds-{random.choice(['local', 'san', 'nfs', 'iscsi'])}-{random.choice(['ssd', 'hdd', 'vmfs', 'nvme'])}-"; name = _ensure_unique_name(name_prefix, SHARED_CONTEXT['datastores'], 20, MAX_NAME_GEN_ATTEMPTS)
    entity = {"id": f"ds-{uuid.uuid4().hex[:8]}", "name": name, "type": name.split('-')[1]}; SHARED_CONTEXT['datastores'][name] = entity
    return entity

def generate_network_entity(current_row_context=None, is_primary_identifier=False, force_new=False, **kwargs):
    if not force_new and not is_primary_identifier and SHARED_CONTEXT['networks'] and random.random() < REUSE_PROBABILITY: return random.choice(list(SHARED_CONTEXT['networks'].values()))
    name_prefix = f"{random.choice(['Prod-Net', 'VLAN', 'Dev-Seg', 'DMZ-Net'])}-"; name = _ensure_unique_name(name_prefix, SHARED_CONTEXT['networks'], 500, MAX_NAME_GEN_ATTEMPTS, suffix_format="{}")
    entity = {"id": f"net-{uuid.uuid4().hex[:8]}", "name": name}; SHARED_CONTEXT['networks'][name] = entity
    return entity

def process_ai_batch(ai_requests):
    responses = {}
    if DEBUG_ENTITY_GENERATION and ai_requests:
        print(f"[DEBUG] Processing batch of {len(ai_requests)} AI requests...")
    for request in ai_requests:
        dummy_response = generate_ai_data(prompt=request['prompt'])
        responses[(request['row_index'], request['column_header'])] = dummy_response
    return responses

def generate_csv_file(base_filename, headers, num_rows_to_generate, column_strategies):
    filepath = os.path.join(CSV_OUTPUT_DIR, base_filename)
    ai_requests_for_this_csv = []
    temp_current_row_context_for_prompts = {}

    for r_idx in range(num_rows_to_generate):
        for header in headers:
            strategy = column_strategies.get(header)
            if strategy and strategy.get('generator') == generate_ai_data:
                prompt_template = strategy.get('args', {}).get('prompt', f"Value for {header}")
                final_prompt = prompt_template
                ai_requests_for_this_csv.append({
                    'row_index': r_idx, 'column_header': header, 'prompt': final_prompt
                })

    ai_processed_responses = {}
    if ai_requests_for_this_csv:
        ai_processed_responses = process_ai_batch(ai_requests_for_this_csv)

    try:
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            for r_idx in range(num_rows_to_generate):
                current_row_context = {}
                row_data = []
                for header in headers:
                    strategy = column_strategies.get(header)
                    generated_value = ""
                    if strategy:
                        generator_func = strategy.get("generator")
                        if generator_func == generate_ai_data:
                            generated_value = ai_processed_responses.get((r_idx, header), "AI_RESPONSE_MISSING")
                        else:
                            args = strategy.get("args", {}); args_to_pass = {**args}
                            is_entity_gen = strategy.get("is_entity_generator", False); attribute_to_extract = strategy.get("attribute_to_extract"); entity_context_key = strategy.get("entity_context_key")
                            sig = inspect.signature(generator_func)
                            if 'current_row_context' in sig.parameters: args_to_pass['current_row_context'] = current_row_context
                            if "min_col_val_from_context" in args and args["min_col_val_from_context"] in current_row_context: args_to_pass["min_val"] = int(current_row_context[args["min_col_val_from_context"]])
                            if "max_col_val_from_context" in args and args["max_col_val_from_context"] in current_row_context: args_to_pass["max_val"] = int(current_row_context[args["max_col_val_from_context"]])
                            if "min_val" in args_to_pass and "max_val" in args_to_pass and args_to_pass["min_val"] > args_to_pass["max_val"]: args_to_pass["max_val"] = args_to_pass["min_val"]
                            cleaned_args_to_pass = {k:v for k,v in args_to_pass.items() if k not in ["is_entity_generator", "attribute_to_extract", "entity_context_key", "source", "entity_context_to_source_from", "attribute", "min_col_val_from_context", "max_col_val_from_context"]}
                            raw_generated_value = generator_func(**cleaned_args_to_pass)
                            if is_entity_gen and entity_context_key:
                                current_row_context[entity_context_key] = raw_generated_value; generated_value = raw_generated_value.get(attribute_to_extract, "")
                            elif strategy.get("source") == "context_entity_attribute":
                                source_key = strategy.get("entity_context_to_source_from"); attr_key = strategy.get("attribute"); entity_in_context = current_row_context.get(source_key)
                                if entity_in_context: generated_value = entity_in_context.get(attr_key, f"ATTR_ERR:{attr_key}")
                                else: generated_value = f"CTX_KEY_ERR:{source_key}"
                            else: generated_value = raw_generated_value
                    else: generated_value = generate_random_string(length=random.randint(5,15))
                    row_data.append(str(generated_value)); current_row_context[header] = generated_value
                writer.writerow(row_data)
        print(f"[SUCCESS] Generated {num_rows_to_generate} rows into {filepath}")
    except Exception as e:
        import traceback
        print(f"ERROR generating {filepath} (Header: {header if 'header' in locals() else 'N/A'}, Row: {r_idx+1 if 'r_idx' in locals() else 'N/A'}): {e}")
        traceback.print_exc()

def zip_generated_csvs(output_zip_filename="RVTools_synthetic_data.zip", generated_files_prefix="generated_"):
    zip_filepath = os.path.join(ZIP_OUTPUT_DIR, output_zip_filename)
    files_zipped_count = 0
    try:
        generated_csv_files = [f for f in os.listdir(CSV_OUTPUT_DIR) if f.startswith(generated_files_prefix) and f.endswith('.csv')]
        if not generated_csv_files:
            print(f"[WARNING] No CSV files found in {CSV_OUTPUT_DIR} with prefix '{generated_files_prefix}' to zip.")
            return
        with zipfile.ZipFile(zip_filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_to_zip_basename in generated_csv_files:
                file_full_path = os.path.join(CSV_OUTPUT_DIR, file_to_zip_basename)
                zipf.write(file_full_path, arcname=file_to_zip_basename)
                os.remove(file_full_path)
                files_zipped_count +=1
        print(f"[SUCCESS] Archive created: {zip_filepath}, containing {files_zipped_count} CSV files.")
        if files_zipped_count > 0:
             print(f"[INFO] Source CSVs removed from {CSV_OUTPUT_DIR} after zipping.")
    except FileNotFoundError:
        print(f"[ERROR] CSV output directory {CSV_OUTPUT_DIR} not found for zipping. Was it created?")
    except Exception as e:
        print(f"[ERROR] Error during zipping: {e}")

def main():
    print("======================================================")
    print("  RVTools Synthetic Data Generator (Placeholder Logo) ")
    print("======================================================")
    print("\n")

    # --- Argument Parsing (Part A) ---
    parser = argparse.ArgumentParser(description="RVTools Synthetic Data Generator")
    parser.add_argument(
        "--rows",
        type=int,
        default=15, # Default if no argument is passed
        help="Number of data rows to generate for each CSV file."
    )
    args = parser.parse_args()
    num_rows_per_csv = args.rows
    print(f"[CONFIG] Generating {num_rows_per_csv} rows per CSV file.")
    # --- End Argument Parsing ---

    # num_rows_per_csv = 2 # Override for quick testing if needed, otherwise controlled by CLI
    max_files_to_process = 3
    files_processed_count = 0

    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)
    os.makedirs(ZIP_OUTPUT_DIR, exist_ok=True)
    print(f"[INFO] Ensured output directories created: {CSV_OUTPUT_DIR}, {ZIP_OUTPUT_DIR}")

    if not SHARED_CONTEXT['dcs']:
        for _ in range(2): generate_datacenter_entity(force_new=True)
    if SHARED_CONTEXT['dcs'] and not SHARED_CONTEXT['clusters']:
        for dc_name in list(SHARED_CONTEXT['dcs'].keys())[:1]:
             for _ in range(1): generate_cluster_entity(current_row_context={'current_dc_entity': SHARED_CONTEXT['dcs'][dc_name]}, force_new=True)
    if SHARED_CONTEXT['clusters'] and not SHARED_CONTEXT['hosts']:
        for cl_name in list(SHARED_CONTEXT['clusters'].keys())[:1]:
            for _ in range(2): generate_host_entity(current_row_context={'current_cluster_entity': SHARED_CONTEXT['clusters'][cl_name]}, force_new=True)

    for csv_filename_key in CSV_GENERATION_ORDER:
        # --- Resume Capability ---
        base_output_filename = f"generated_{csv_filename_key}"
        expected_filepath = os.path.join(CSV_OUTPUT_DIR, base_output_filename)
        if os.path.exists(expected_filepath):
            print(f"[INFO] File already exists: {expected_filepath}. Skipping generation.")
            # files_processed_count +=1 # Don't increment here, or max_files might be skipped before actual processing
            continue
        # --- End Resume Capability ---

        if files_processed_count >= max_files_to_process: # Check before preparing to generate
            print(f"[INFO] Reached max_files_to_process ({max_files_to_process}). Stopping further CSV generation for this test run.")
            break

        print(f"\n[INFO] Preparing to generate: {base_output_filename}...")

        if csv_filename_key not in CSV_HEADERS:
            print(f"[WARNING] {csv_filename_key} in generation order but not in CSV_HEADERS. Skipping actual generation.")
            files_processed_count +=1 # Count as "processed" to advance loop if only a few files have headers for testing
            continue

        headers_list = CSV_HEADERS[csv_filename_key]
        column_strategies = {}
        is_defining_dcs = "tabvhost" in csv_filename_key.lower()
        is_defining_clusters = "tabvhost" in csv_filename_key.lower()
        is_defining_hosts = "tabvhost" in csv_filename_key.lower()
        is_defining_vms = "tabvinfo" in csv_filename_key.lower()
        is_defining_networks = "tabvnetwork" in csv_filename_key.lower() or "tabvswitch" in csv_filename_key.lower() or "tabvport" in csv_filename_key.lower()
        is_defining_datastores = "tabvdatastore" in csv_filename_key.lower()

        for header in headers_list:
            header_lower = header.lower()
            column_strategies[header] = {"generator": generate_random_string, "args": {"length": random.randint(6, 12)}}
            if header == "Datacenter": column_strategies[header] = {"generator": generate_datacenter_entity, "args": {"is_primary_identifier": is_defining_dcs, "force_new": is_defining_dcs and len(SHARED_CONTEXT['dcs']) < num_rows_per_csv * 0.2}, "is_entity_generator": True, "attribute_to_extract": "name", "entity_context_key": "current_dc_entity"}
            elif header == "Cluster": column_strategies[header] = {"generator": generate_cluster_entity, "args": {"is_primary_identifier": is_defining_clusters, "force_new": is_defining_clusters and len(SHARED_CONTEXT['clusters']) < num_rows_per_csv * 0.5}, "is_entity_generator": True, "attribute_to_extract": "name", "entity_context_key": "current_cluster_entity"}
            elif header == "ESX Host": column_strategies[header] = {"generator": generate_host_entity, "args": {"is_primary_identifier": is_defining_hosts, "force_new": is_defining_hosts and len(SHARED_CONTEXT['hosts']) < num_rows_per_csv}, "is_entity_generator": True, "attribute_to_extract": "name", "entity_context_key": "current_host_entity"}
            elif header == "DNS Name" and is_defining_vms: column_strategies[header] = {"generator": generate_vm_entity, "args": {"is_primary_identifier": True, "force_new":True}, "is_entity_generator": True, "attribute_to_extract": "name", "entity_context_key": "current_vm_entity"}
            elif header == "DNS Name": column_strategies[header] = {"generator": generate_vm_entity, "args": {"is_primary_identifier": False}, "is_entity_generator": True, "attribute_to_extract": "name", "entity_context_key": "current_vm_entity"}
            elif header == "VM ID": column_strategies[header] = {"source": "context_entity_attribute", "entity_context_to_source_from": "current_vm_entity", "attribute": "id", "fallback_generator": generate_random_string, "fallback_args":{"length":12}}
            elif header == "IP Address":
                if "vm" in csv_filename_key.lower() or ("nic" in csv_filename_key.lower() and "host" not in csv_filename_key.lower()) : column_strategies[header] = {"source": "context_entity_attribute", "entity_context_to_source_from": "current_vm_entity", "attribute": "ip", "fallback_generator": generate_ip_address}
                elif "host" in csv_filename_key.lower() and "nic" in csv_filename_key.lower(): column_strategies[header] = {"source": "context_entity_attribute", "entity_context_to_source_from": "current_host_entity", "attribute": "ip", "fallback_generator": generate_ip_address}
                else: column_strategies[header] = {"generator": generate_ip_address}
            elif header == "MAC Address": column_strategies[header] = {"source": "context_entity_attribute", "entity_context_to_source_from": "current_vm_entity", "attribute": "mac", "fallback_generator": generate_mac_address}
            elif header_lower == "powerstate": column_strategies[header] = {"source": "context_entity_attribute", "entity_context_to_source_from": "current_vm_entity", "attribute": "powerstate", "fallback_generator": generate_power_state}
            elif "os according to the vmware tools" in header_lower or "os according to the configuration file" in header_lower: column_strategies[header] = {"source": "context_entity_attribute", "entity_context_to_source_from": "current_vm_entity", "attribute": "os", "fallback_generator": generate_os_name}
            elif header == "Datastore" or "datastore name" in header_lower: column_strategies[header] = {"generator": generate_datastore_entity, "args": {"is_primary_identifier": is_defining_datastores, "force_new": is_defining_datastores and len(SHARED_CONTEXT['datastores']) < num_rows_per_csv * 0.3}, "is_entity_generator": True, "attribute_to_extract": "name", "entity_context_key": "current_datastore_entity"}
            elif "network adapter" in header_lower or "port group" in header_lower or "switch name" in header_lower or (header_lower.startswith("network #") and is_defining_vms): column_strategies[header] = {"generator": generate_network_entity, "args": {"is_primary_identifier": is_defining_networks, "force_new": is_defining_networks and len(SHARED_CONTEXT['networks']) < num_rows_per_csv * 0.5}, "is_entity_generator": True, "attribute_to_extract": "name", "entity_context_key": "current_network_entity"}
            elif "vmware tools" == header_lower or "tools version" in header_lower or "tools status" in header_lower: column_strategies[header] = {"generator": generate_tools_status}
            elif "status" in header_lower and "tools" not in header_lower: column_strategies[header] = {"generator": generate_generic_status}
            elif "message" == header_lower: column_strategies[header] = {"generator": generate_ai_data, "args": {"prompt": f"Generate a {header} for {csv_filename_key}"}}
            elif "annotations" == header_lower : column_strategies[header] = {"generator": generate_ai_data, "args": {"prompt": f"Generate realistic VM annotation for a VM named [VM_NAME] running [OS_TYPE] for purpose [PURPOSE_TAG]. Include project codes, owner, or EOL dates."}}
            elif "capacity mb" == header_lower or "provisioned mb" == header_lower: column_strategies[header] = {"generator": generate_random_integer, "args": {"min_val": 10240, "max_val": 204800}}
            elif "used mb" == header_lower or "in use mb" == header_lower:  column_strategies[header] = {"generator": generate_random_integer, "args": {"min_val": 5120, "max_val": 102400, "max_col_val_from_context": "Capacity MB"}}
            elif "free mb" == header_lower : column_strategies[header] = {"generator": generate_random_integer, "args": {"min_val": 1024, "max_val": 102400, "max_col_val_from_context":"Provisioned MB"}}
            elif "capacity gb" == header_lower or "provisioned gb" == header_lower: column_strategies[header] = {"generator": generate_random_integer, "args": {"min_val": 20, "max_val": 4096}}
            elif "used gb" == header_lower or "in use gb" == header_lower: column_strategies[header] = {"generator": generate_random_integer, "args": {"min_val": 10, "max_val": 2048, "max_col_val_from_context":"Capacity GB"}}
            elif "free gb" == header_lower: column_strategies[header] = {"generator": generate_random_integer, "args": {"min_val": 1, "max_val": 2048, "max_col_val_from_context":"Provisioned GB"}}
            elif "%" in header.lower(): column_strategies[header] = {"generator": generate_random_integer, "args": {"min_val":0, "max_val":100}}
            elif "date" in header_lower or "created" in header_lower or "modified" in header_lower or "time" in header_lower or "expiration" in header_lower: column_strategies[header] = {"generator": generate_datetime_string}
            elif "enabled" in header_lower or ("connected" in header_lower and "connect at power on" not in header_lower) or "is " in header_lower or "protected" in header_lower or "ssd" in header_lower or "local" in header_lower or "thin" in header_lower: column_strategies[header] = {"generator": generate_boolean_string}
            elif "connect at power on" in header_lower: column_strategies[header] = {"generator": generate_boolean_string, "args": {"true_val": "yes", "false_val": "no"}}
            elif ("id" in header_lower or "key" in header_lower) and "vm id" not in header_lower and "uuid" not in header_lower : column_strategies[header] = {"generator": generate_random_string, "args": {"length": 8}}
            elif "uuid" in header_lower: column_strategies[header] = {"generator": generate_random_string, "args": {"length":36}}
            elif "user" in header_lower or "contact" in header_lower or "licensed to" in header_lower or "product name" in header_lower or "description" in header_lower or "annotations" in header_lower: column_strategies[header] = {"generator": generate_random_string, "args": {"length": random.randint(15,50)}}
            elif "folder" in header_lower or "logdirectory" in header_lower or "path" in header_lower: column_strategies[header] = {"generator": generate_random_string, "args":{"length":random.randint(20,60)}}

        generate_csv_file(base_output_filename, headers_list, num_rows_per_csv, column_strategies)
        files_processed_count +=1

    print("\n[INFO] CSV generation phase complete.")
    print("[INFO] Starting zipping process...")
    zip_generated_csvs()

    print("--- Shared Context Overview (Final) ---")
    for key, entity_dict in SHARED_CONTEXT.items():
        if isinstance(entity_dict, dict): print(f"{key}: {len(entity_dict)} unique entities created. Examples: {list(entity_dict.keys())[:3]}")
        elif isinstance(entity_dict, list): print(f"{key}: {len(entity_dict)} unique items. Examples: {entity_dict[:3]}")
    print("\nRVTools Synthetic Data Generator finished.")

if __name__ == "__main__":
    main()

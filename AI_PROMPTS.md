# AI Prompts for RVTools Synthetic Data Generation

This document provides example prompts that can be used with a generative AI model to create more nuanced and realistic data for specific fields in the RVTools CSV files. The `rvtools_data_generator.py` script includes a placeholder `generate_ai_data(prompt)` function; these prompts are designed to be used with such a function if it were connected to a real AI.

The placeholders like `[VM_NAME]`, `[OS_TYPE]`, `[PURPOSE_TAG]`, `[DATACENTER_NAME]`, `[ESX_HOST_VENDOR]`, `[ESX_HOST_MODEL]` should be replaced with actual generated data from other columns for the same row or related entities to provide context to the AI.

## 1. RVTools_tabvInfo.csv

### Column: `Annotations`
**Prompt:**
"Generate a brief, realistic VMware VM annotation for a virtual machine named `[VM_NAME]` running `[OS_TYPE]`. The VM's business purpose is `[PURPOSE_TAG]` (e.g., 'Critical Financial Reporting', 'Development Web Server', 'Batch Processing Unit'). The annotation should be 1-3 sentences long and might include information like:
- Project code or cost center (e.g., PROJ-123, CC-FINANCE).
- Primary application owner or team (e.g., Owner: FinApp Team, Contact: devops@example.com).
- Expected EOL date or review date (e.g., EOL: 2025-12-31, Review: Q3/2024).
- A brief note about its function or any special considerations.

Example for context: If VM is 'prod-db-01', OS is 'Linux', Purpose is 'Core Database Server'.
A good annotation might be: 'PROJ-007; CC-COREDB. Primary Oracle database server for CRM application. Owner: DBAdmins. Critical service - do not power off without approval. Review performance Q1/2024.'"

### Column: `VM Folder`
**Prompt:**
"Suggest a realistic VMware VM folder path for a virtual machine named `[VM_NAME]` located in datacenter `[DATACENTER_NAME]`. The VM's purpose is `[PURPOSE_TAG]`. The folder structure should reflect common organizational patterns.
Possible top-level folders could be: 'Production', 'Development', 'Test', 'Staging', 'CoreInfrastructure', 'BusinessUnitA'.
Possible sub-folders could be by OS type (e.g., 'Windows', 'Linux'), application name/type (e.g., 'SQLServers', 'WebServers', 'OracleDBs'), or department.

Example for context: VM 'dev-web-03', Datacenter 'DC-Development', Purpose 'Web Development Server'.
A good folder path might be: '/[DATACENTER_NAME]/Development/WebServers/' or '/[DATACENTER_NAME]/Sandbox/Linux/FrontendApps/'"


## 2. RVTools_tabvHost.csv

### Column: `Model` (based on `Vendor`)
**Prompt:**
"Given an ESX Host vendor `[ESX_HOST_VENDOR]`, generate a plausible server model name.
- If Vendor is 'Dell Inc.', suggest models like 'PowerEdge R740', 'PowerEdge R650', 'PowerEdge MX750c'.
- If Vendor is 'HP' or 'HPE', suggest models like 'ProLiant DL380 Gen10', 'ProLiant DL360 Gen11', 'Synergy 480 Gen10'.
- If Vendor is 'Lenovo', suggest models like 'ThinkSystem SR650', 'ThinkSystem SR630'.
- If Vendor is 'Supermicro', suggest models like 'SuperServer SYS-1029P-WTRT'.
- If Vendor is 'Cisco Systems Inc', suggest models like 'UCS B200 M5', 'UCS C240 M6'.
If the vendor is less common or generic, generate a plausible alphanumeric model name like 'SystemX-3650 M5' or 'EnterpriseServ-2U-Gold'.

Context: Vendor is `[ESX_HOST_VENDOR]`."

### Column: `Custom Fields` (Example: Asset Tag or Environment)
**Prompt:**
"For an ESX Host named `[ESX_HOST_NAME]` in cluster `[CLUSTER_NAME]`, generate a set of 2-3 example custom field key-value pairs that might be defined in vCenter. These should be formatted as 'Key1=Value1; Key2=Value2'.
Example custom fields could be:
- 'AssetTag': e.g., 'AT12345XYZ'
- 'Environment': e.g., 'Production', 'Staging', 'Development-Lab'
- 'RackLocation': e.g., 'R10-U25'
- 'PurchaseDate': e.g., '2022-08-15'
- 'SupportContractID': e.g., 'SUP98765'

Generate a string combining 2-3 such pairs."


## 3. RVTools_tabvDatastore.csv

### Column: `Datastore` (Name)
**Prompt:**
"Generate a realistic VMware datastore name. The datastore has the following characteristics:
- Storage Type (choose one or combine): `[STORAGE_TYPE_HINT]` (e.g., 'SSD-Tier1', 'SATA-Tier2', 'NVMe-Fast', 'Local-ESXi', 'SAN-LUN', 'NFS-Share')
- Primary Purpose/Workload (choose one): `[WORKLOAD_HINT]` (e.g., 'VM-Templates', 'Production-DBs', 'DevTest-VMs', 'ISO-Images', 'Backup-Target')
- (Optional) Datacenter or Cluster context: `[LOCATION_CONTEXT]` (e.g., 'DC1', 'ClusterA')

The name should be somewhat descriptive and follow common naming conventions, like including hints about tier, protocol, or purpose.

Example for context: Storage Type 'SAN-LUN-FC', Workload 'Production-VMs', Location 'DC-Frankfurt'.
A good datastore name might be: 'DS_PROD_VMs_FC_LUN05_DCFRA' or 'frankfurt-prod-vm-storage-01'."


## 4. RVTools_tabvNetwork.csv

### Column: `Port Group` / `Switch Name`
**Prompt:**
"Generate a realistic VMware port group name or vSwitch name. The network serves VMs with purpose `[PURPOSE_TAG]` (e.g., 'DMZ Web Servers', 'Internal App Servers', 'Management Network', 'vMotion Network') and might be associated with VLAN ID `[VLAN_ID]`.

Consider these naming patterns:
- Include purpose: 'PG_DMZ_Web', 'vSwitch_Production_Apps'
- Include VLAN ID: 'VLAN_[VLAN_ID]_DevTest', 'PG_VLAN[VLAN_ID]'
- Generic but structured: 'VM_Network_Alpha', 'BackendSwitch01'

Context: Purpose `[PURPOSE_TAG]`, VLAN ID `[VLAN_ID]`."


## 5. RVTools_tabvHealth.csv

### Column: `Message`
**Prompt:**
"Generate a concise, realistic health check message for a VMware entity. The entity is `[OBJECT_TYPE]` named `[OBJECT_NAME]`. The health status is `[HEALTH_STATUS]` (e.g., 'Ok', 'Warning', 'Error', 'Unknown').

- If status is 'Ok', message can be simple like 'Health check successful.' or 'No issues detected.'
- If status is 'Warning', message should indicate a non-critical issue. Examples: 'High CPU utilization observed.', 'Guest disk space running low.', 'VMware Tools out of date.'
- If status is 'Error', message should indicate a critical issue. Examples: 'Host disconnected from vCenter.', 'Datastore inaccessible.', 'VM heartbeat failure.'
- If status is 'Unknown', message could be 'Health status could not be determined.'

The message should be specific to the object type if possible.
Context: Object Type `[OBJECT_TYPE]`, Object Name `[OBJECT_NAME]`, Status `[HEALTH_STATUS]`."

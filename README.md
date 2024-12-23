# ahv-ipam-ddns 

AHV IPAM DDNS Integration  
A Bash script for synchronizing DNS with Nutanix AHV-managed IPAM leases using dynamic DNS updates  
  
## Overview
The AHV IPAM DDNS Integration script provides an automated solution for synchronizing DNS records with Nutanix AHV-managed IPAM leases using secure TSIG-authenticated DDNS updates. Designed for environments relying on Nutanix AHV IPAM, the script dynamically retrieves VM lease data, updates DNS records, and cleans up stale entries to maintain a consistent and accurate DNS state.  

This first version supports Nutanix Basic VLANs only. It does not support Network Controller-based VLANs. Support for these will be added in a future release.

## Features
-  Dynamic DNS Updates: Automatically updates DNS records to reflect IPAM-managed leases.
-  Customizable Hostnames: Supports a substitution file for mapping VM names to preferred DNS hostnames.
-  Cleanup of Stale Records: Automatically removes outdated DNS entries based on a configurable timeout.
-  Centralized Configuration: Stores all settings in a JSON configuration file for easy management.
-  Vault Integration: Securely retrieves sensitive information such as TSIG keys and database credentials from HashiCorp Vault.
-  Logging: Logs all script actions and cron job outputs for debugging and tracking.
-  Cron Job Automation: Automates periodic polling, DDNS updates, and stale record cleanup.

## Requirements
Software Requirements
-  Nutanix AHV: Requires API access to Prism Central.
-  DNS Server: FreeIPA or BIND with support for TSIG-based DDNS updates.
-  PostgreSQL: Database for tracking leases and managing cleanup.
-  HashiCorp Vault: Secure storage for secrets such as TSIG keys and database credentials.

## Additional Dependencies
-  jq: For parsing JSON.
-  curl: For API requests.
-  psql: PostgreSQL CLI tool.
-  nsupdate: For DDNS updates.
- ahv_ipam_ddns.json must be in proper JSON format and validated (e.g., using jq)

## User Credentials and Permissions
-  PostgreSQL User: The script expects a user named ahv_admin with permissions to create and manage tables in the specified database.
   You can pre-create the leases table if permissions are restricted.
-  HashiCorp Vault Setup:
     Store the following secrets in HashiCorp Vault:
     - Prism Central Credentials: secret/nutanix/prism_central_ip and secret/nutanix/encoded_credentials
       This can be done using the script (ahv_ipam_ddns save_credentials) if vault access policy allows
     - PostgreSQL Credentials: secret/ipa/psql/ahv_admin
     - TSIG Key: secret/ipa/dns

Vault must be unsealed and accessible from the host running the script.

## Installation and Setup
Step 1: Clone the Repository  
	  git clone https://github.com/steve-eyler/ahv-ipam-ddns  
	  cd ahv-ipam-ddns  
  
Step 2: Configure the JSON File  
Edit the ahv_ipam_ddns.json configuration file:  
  
```json
{
    "dns_ip_address": "10.1.150.101",
    "domain_name": "lab.steveeyler.com",
    "nutanix_polling_interval": 5,
    "stale_entry_timeout": 300,
    "hostname_substitution_file": "ddns_hostnames.csv",
    "debug_enabled": false,
    "postgres_host": "10.1.150.101",
    "ahv_ipam_db": "ahv_ipam_db"
}
```
  
Step 3: Add Hostname Substitution File (optional)  
  Specify a file in the config (default ddns_hostnames.csv) to map vm names to preferred hostnames in the format:  
```
    normalized_vm_name,preferred_hostname
    lab-softwaredistribution,lcm
    lab-wireshark,wireshark
    se-saratoga,saratoga
    se-stargazer,stargazer
    se-valiant,valiant
```

Step 4: Save Prism Central Credentials to Vault

Run the following command to store Prism Central credentials in Vault:  
	  ./ahv_ipam_ddns.sh save_credentials {prism_central_ip} {username} {password}

Replace {prism_central_ip}, {username}, and {password} with your Prism Central details.  
This will store the credentials in Vault at secret/nutanix/prism_central_ip and secret/nutanix/encoded_credentials

Step 5: Create the Database  

Run the script to create the required database and table:
	  ./ahv_ipam_ddns.sh create_db

This will:
-  Create the leases table in the database specified in the configuration file.
-  Ensure the ahv_admin user has the necessary permissions.

Step 6: Retrieve the current IP assignments  
	  ./ahv_ipam_ddns.sh get_leases

Step 7: Examine the database  
	  ./ahv_ipam_ddns.sh show_leases

Step 8. Update DNS via DDNS  
	  ./ahv_ipam_ddns.sh update_dns

Step 9. Update with Cron  
	  ./ahv_ipam_ddns.sh setup_cron

The cron job will:
-  Retrieve VM leases
-  Update DNS records
-  Clean up stale entries

## Usage

Manual Execution  
  Run individual functions as needed:  

  Store Prism Central Credentials:  
    ./ahv_ipam_ddns.sh save_credentials {prism_central_ip} {username} {password}  
  
  Retrieve Leases:  
    ./ahv_ipam_ddns.sh get_leases  
    
  Show Lease Database:  
    ./ahv_ipam_ddns.sh show_leases  
  
  Update DNS:  
    ./ahv_ipam_ddns.sh update_ddns  
    
  Clean Up Stale Entries:  
    ./ahv_ipam_ddns.sh cleanup_leases  
  
Verify Logs  
All output is written to /var/log/ahv_ipam.log by default. Check the log for details:  
  
tail -f /var/log/ahv_ipam.log  
  
## Notes and Limitations

<b>Basic VLANs Only</b>: This version supports only Nutanix Basic VLANs. Network Controller VLAN support will be added in a future release.  
<b>Vault Requirement</b>: The script relies on HashiCorp Vault for securely storing secrets. Ensure Vault is set up and accessible. You can replace the HashiCorp Vault requirement with alternate secret handling in the script if desired.  
<b>Flexibility</b>: While written for a specific use case, the script includes comments and can be modified to work with other environments and configurations. get_leases() syncs the IPAM leases with the psql database. Pushing DDNS updates with nsupdate is a separate and optional function.

Contributing
Contributions are welcome. If you have suggestions, find a bug, or want to add a feature, feel free to open an issue or submit a pull request.

License
This project is licensed under the Apache License 2.0. See the LICENSE file for details.

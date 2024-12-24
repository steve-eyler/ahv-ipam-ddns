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
-  DNS Server: Support for TSIG-based DDNS updates using ```nsupdate```  
   Tested with FreeIPA 4.12.2 and BIND 9.16.23-RH  
-  PostgreSQL: Database for tracking leases and managing cleanup.
-  HashiCorp Vault: Secure storage for secrets such as TSIG keys and database credentials.

## Additional Dependencies
-  ```jq```: For parsing JSON.
-  ```curl```: For API requests.
-  ```psql```: PostgreSQL CLI tool.
-  ```nsupdate```: For DDNS updates.
-  ```ahv_ipam_ddns.json``` must be in proper JSON format and validated (e.g., using jq)

## User Credentials and Permissions
-  PostgreSQL User: The script expects a user named ahv_admin with permissions to create and manage tables in the specified database.
   You can pre-create the leases table if permissions are restricted.
-  HashiCorp Vault Setup:
     Store the following secrets in HashiCorp Vault:  
     - Prism Central Credentials: ```secret/nutanix/prism_central_ip``` and ```secret/nutanix/encoded_credentials```  
       This can be done using the script (```ahv_ipam_ddns save_credentials```) if vault access policy allows  
     - PostgreSQL Credentials: ```secret/ipa/psql/ahv_admin```  
     - TSIG Key: ```secret/ipa/dns```  

Vault must be unsealed and accessible from the host running the script.

## Installation and Setup
<b>Step 1</b>: Clone the Repository  
   ```bash
   git clone https://github.com/steve-eyler/ahv-ipam-ddns
   cd ahv-ipam-ddns
   ```

<b>Step 2</b>: Enable autocomplete (optional)  
Source the autocomplete file:  
   ```bash
   source ./ahv_ipam_ddns.completion
   ```

(Optional) Add the file to your `.bashrc` or `.bash_profile` to enable autocomplete permanently:  
   ```bash
   echo 'source /path/to/ahv_ipam_ddns.completion' >> ~/.bashrc
   ```  

<b>Step 3</b>: Configure the JSON File  
Edit the ahv_ipam_ddns.json configuration file with your settings. In the current version, ```nutanix_polling_interval``` is specified in minutes, while ```stale_entry_timeout``` is specified in seconds.  
  
```json
{
    "dns_ip_address": "10.1.150.101",
    "domain_name": "lab.steveeyler.com",
    "nutanix_polling_interval": 5,
    "stale_entry_timeout": 300,
    "hostname_substitution_file": "ddns_hostnames.csv",
    "log_level": 0,
    "postgres_host": "10.1.150.101",
    "ahv_ipam_db": "ahv_ipam_db"
}
```
  
<b>Step 4</b>: Add Hostname Substitution File (optional)  
You can specify a file in the configuration (default: ddns_hostnames.csv) to map VM names to preferred hostnames. When VM names are retrieved from Prism Central, they are normalized to remove spaces and special characters.  

To view the normalized names, use the ```get_names``` command after running ```get_leases```. These normalized names will be used for registering the host with DNS. During the ```update_ddns``` process, a lookup will be performed against the normalized name. If a preferred hostname is specified, it will be used during DNS registration.  

The hostname substitution CSV file should follow this format:  
```normalized_vm_name,preferred_hostname```

Example:
```
    lab-softwaredistribution,lcm
    lab-wireshark,wireshark
    se-saratoga,saratoga
    se-stargazer,stargazer
    se-valiant,valiant
    client-windows10-spock,spock
```

<b>Step 5</b>: Save Prism Central Credentials to Vault

Run the following command to store Prism Central credentials in Vault:  
	  ```./ahv_ipam_ddns.sh save_credentials {prism_central_ip} {username} {password}```

Replace ```{prism_central_ip}```, ```{username}```, and ```{password}``` with your Prism Central details.  
This will store the credentials in Vault at ```secret/nutanix/prism_central_ip``` and ```secret/nutanix/encoded_credentials```

<b>Step 6</b>: Create the Database  

Run the script to create the required database and table:
	  ```./ahv_ipam_ddns.sh create_db```

This will:
-  Create the leases table in the database specified in the configuration file.
-  Ensure the ahv_admin user has the necessary permissions.

<b>Step 7</b>: Retrieve the current IP assignments  
	  ```./ahv_ipam_ddns.sh get_leases```

<b>Step 8</b>: Update DNS via DDNS  
	  ```./ahv_ipam_ddns.sh update_dns```

<b>Step 9</b>: Update with Cron  
	  ```./ahv_ipam_ddns.sh setup_cron```  

This will automatically enter a cronjob for the current user, based on settings in the config file, that will schedule recurring:
-  Retrieve VM leases
-  Update DNS records
-  Clean up stale entries

## Usage

Manual Execution  
  Run individual functions as needed:  

  Store Prism Central Credentials:  
    ```./ahv_ipam_ddns.sh save_credentials {prism_central_ip} {username} {password}```  
  
  Retrieve Leases - Query Prism Central for IP addresses on Nutanix IPAM-managed VLANs:  
    ```./ahv_ipam_ddns.sh get_leases```  
    
  Show Lease Database - Query and display contents of psql lease table:  
    ```./ahv_ipam_ddns.sh show_leases```  
  
  Update DNS - Update DNS with least table via DDNS for hosts that do not already have A or PTR records):  
    ```./ahv_ipam_ddns.sh update_ddns```  
    
  Clean Up Stale Entries (removes stale entries from leases db and ddns):  
    ```./ahv_ipam_ddns.sh cleanup_leases```  

  Reset Database (removes all entries, does not affect ddns):  
    ```./ahv_ipam_ddns.sh reset_db```  

  Prune specific entries from the leases table and DDNS:  
    ```./ahv_ipam_ddns.sh prune_db <ip_or_hostname_1> [<ip_or_hostname_2> ...]```   
  
Verify Logs  
All output is written to /var/log/ahv_ipam.log by default. Check the log for details:  
  
```tail -f /var/log/ahv_ipam.log```  
  
## Notes and Limitations  

<b>Basic VLANs Only</b>: This version supports only Nutanix Basic VLANs. Network Controller VLAN support will be added in a future release.  

<b>Vault Requirement</b>: The script relies on HashiCorp Vault for securely storing secrets. Ensure Vault is set up and accessible. You can replace the HashiCorp Vault requirement with alternate secret handling in the script if desired.   

<b>Contributing</b>: Contributions are welcome. If you have suggestions, find a bug, or want to add a feature, feel free to open an issue or submit a pull request.  

License  
This project is licensed under the Apache License 2.0. See the LICENSE file for details.  


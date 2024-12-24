# ahv-ipam-ddns

AHV IPAM DDNS Integration
A Bash script for synchronizing DNS with Nutanix AHV-managed IPAM leases using dynamic DNS updates.

## Overview
The AHV IPAM DDNS Integration script provides an automated solution for synchronizing DNS records with Nutanix AHV-managed IPAM leases using secure TSIG-authenticated DDNS updates. Designed for environments relying on Nutanix AHV IPAM, the script dynamically retrieves VM lease data, updates DNS records, and cleans up stale entries to maintain a consistent and accurate DNS state.

This first version supports Nutanix Basic VLANs only. It does not support Network Controller-based VLANs. Support for these will be added in a future release.

## Features
- **Dynamic DNS Updates**: Automatically updates DNS records to reflect IPAM-managed leases.
- **Customizable Hostnames**: Supports a substitution file for mapping VM names to preferred DNS hostnames.
- **Cleanup of Stale Records**: Automatically removes outdated DNS entries based on a configurable timeout.
- **Centralized Configuration**: Stores all settings in a JSON configuration file for easy management.
- **Vault Integration**: Securely retrieves sensitive information such as TSIG keys and database credentials from HashiCorp Vault.
- **Logging**: Logs all script actions and cron job outputs for debugging and tracking.
- **Cron Job Automation**: Automates periodic polling, DDNS updates, and stale record cleanup.

## Requirements
### Software Requirements
- **Nutanix AHV**: Requires API access to Prism Central.
- **DNS Server**: FreeIPA or BIND with support for TSIG-based DDNS updates.
- **PostgreSQL**: Database for tracking leases and managing cleanup.
- **HashiCorp Vault**: Secure storage for secrets such as TSIG keys and database credentials.

### Additional Dependencies
- `jq`: For parsing JSON.
- `curl`: For API requests.
- `psql`: PostgreSQL CLI tool.
- `nsupdate`: For DDNS updates.
- Configuration file: `ahv_ipam_ddns.json` must be in proper JSON format and validated (e.g., using `jq`).

### User Credentials and Permissions
- **PostgreSQL User**: The script expects a user named `ahv_admin` with permissions to create and manage tables in the specified database. You can pre-create the leases table if permissions are restricted.
- **HashiCorp Vault Setup**: Store the following secrets in HashiCorp Vault:
  - **Prism Central Credentials**: `secret/nutanix/prism_central_ip` and `secret/nutanix/encoded_credentials` (This can be done using the script `ahv_ipam_ddns save_credentials` if vault access policy allows).
  - **PostgreSQL Credentials**: `secret/ipa/psql/ahv_admin`.
  - **TSIG Key**: `secret/ipa/dns`.

Vault must be unsealed and accessible from the host running the script.

## Installation and Setup
### Step 1: Clone the Repository
```bash
git clone https://github.com/steve-eyler/ahv-ipam-ddns
cd ahv-ipam-ddns
```

### Step 2: Enable Autocomplete (Optional)
Source the autocomplete file:
```bash
source ./ahv_ipam_ddns.completion
```
(Optional) Add the file to your `.bashrc` or `.bash_profile` to enable autocomplete permanently:
```bash
echo 'source /path/to/ahv_ipam_ddns.completion' >> ~/.bashrc
```

### Step 3: Configure the JSON File
Edit the `ahv_ipam_ddns.json` configuration file with your settings. In the current version, `nutanix_polling_interval` is specified in minutes, while `stale_entry_timeout` is specified in seconds.

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

### Step 4: Add Hostname Substitution File (Optional)
You can specify a file in the configuration (default: `ddns_hostnames.csv`) to map VM names to preferred hostnames. When VM names are retrieved from Prism Central, they are normalized to remove spaces and special characters.

To view the normalized names, use the `get_names` command after running `get_leases`. These normalized names will be used for registering the host with DNS. During the `update_ddns` process, a lookup will be performed against the normalized name. If a preferred hostname is specified, it will be used during DNS registration.

The hostname substitution CSV file should follow this format:
```csv
normalized_vm_name,preferred_hostname
```

**Example:**
```csv
lab-softwaredistribution,lcm
lab-wireshark,wireshark
se-saratoga,saratoga
se-stargazer,stargazer
se-valiant,valiant
client-windows10-spock,spock
```

### Step 5: Save Prism Central Credentials to Vault
Run the following command to store Prism Central credentials in Vault:
```bash
./ahv_ipam_ddns.sh save_credentials {prism_central_ip} {username} {password}
```
Replace `{prism_central_ip}`, `{username}`, and `{password}` with your Prism Central details. This will store the credentials in Vault at `secret/nutanix/prism_central_ip` and `secret/nutanix/encoded_credentials`.

### Step 6: Create the Database
Run the script to create the required database and table:
```bash
./ahv_ipam_ddns.sh create_db
```
This will:
- Create the leases table in the database specified in the configuration file.
- Ensure the `ahv_admin` user has the necessary permissions.

### Step 7: Retrieve the Current IP Assignments
```bash
./ahv_ipam_ddns.sh get_leases
```

### Step 8: Update DNS via DDNS
```bash
./ahv_ipam_ddns.sh update_ddns
```

### Step 9: Automate with Cron
```bash
./ahv_ipam_ddns.sh setup_cron
```
This will automatically enter a cron job for the current user, based on settings in the config file, that will schedule recurring:
- Retrieve VM leases.
- Update DNS records.
- Clean up stale entries.

## Usage
### Manual Execution
Run individual functions as needed:

- **Store Prism Central Credentials:**
  ```bash
  ./ahv_ipam_ddns.sh save_credentials {prism_central_ip} {username} {password}
  ```

- **Retrieve Leases:** Query Prism Central for IP addresses on Nutanix IPAM-managed VLANs:
  ```bash
  ./ahv_ipam_ddns.sh get_leases
  ```
  This command polls Prism Central for subnets and VMs, then inserts IPAM-managed IP addresses into the PostgreSQL database specified in the configuration file.

- **Show Lease Database:** Query and display contents of the PostgreSQL lease table:
  ```bash
  ./ahv_ipam_ddns.sh show_leases
  ```

- **Update DNS:** Update DNS with lease table entries via DDNS for hosts that do not already have `A` or `PTR` records:
  ```bash
  ./ahv_ipam_ddns.sh update_ddns
  ```
  `nsupdate` uses DDNS to update DNS with managed IP addresses and hostnames. If a DNS entry exists for the hostname or a reverse lookup entry exists for the IP address, no DDNS update will be made.

- **Clean Up Stale Entries:** Remove stale entries from the leases database and DDNS:
  ```bash
  ./ahv_ipam_ddns.sh cleanup_leases
  ```
  `nsupdate` uses DDNS to remove DNS entries for IP addresses no longer present in the response from Nutanix. Hosts with pre-existing static entries will not be removed from either DNS or the lease table.

- **Reset Database:** Remove all entries (does not affect DDNS):
  ```bash
  ./ahv_ipam_ddns.sh reset_db
  ```

- **Prune Specific Entries:** Remove specific IP addresses or hostnames from the database and DDNS:
  ```bash
  ./ahv_ipam_ddns.sh prune_db <ip_or_hostname_1> [<ip_or_hostname_2> ...]
  ```

### Verify Logs
All output is written to `/var/log/ahv_ipam.log` by default. Check the log for details:
```bash
tail -f /var/log/ahv_ipam.log
```

## Detailed Function Descriptions

### `save_credentials`
**Purpose:** Store Prism Central credentials in Vault.

**Command:**
```bash
./ahv_ipam_ddns.sh save_credentials {prism_central_ip} {username} {password}
```
- **Parameters:**
  - `prism_central_ip`: IP address of Prism Central.
  - `username`: Username for Prism Central authentication.
  - `password`: Password for Prism Central authentication.

**Behavior:**
- Validates the provided credentials against Prism Central.
- Stores the encoded credentials and Prism Central IP in Vault.

### `get_leases`
**Purpose:** Query Prism Central for IP addresses on Nutanix IPAM-managed VLANs and populate the database.

**Command:**
```bash
./ahv_ipam_ddns.sh get_leases
```

**Behavior:**
- Retrieves VM lease data from Prism Central.
- Inserts IPAM-managed IP addresses into the database.
- Does not overwrite the `preexisting_dns` field if it already exists.

### `show_leases`
**Purpose:** Display all active leases in the database.

**Command:**
```bash
./ahv_ipam_ddns.sh show_leases
```

**Behavior:**
- Queries the PostgreSQL `leases` table and displays its contents.

### `update_ddns`
**Purpose:** Update DNS with lease table entries via DDNS for hosts that do not already have `A` or `PTR` records.

**Command:**
```bash
./ahv_ipam_ddns.sh update_ddns
```

**Behavior:**
- Checks existing DNS records for each entry in the database.
- Updates DNS using `nsupdate` if no existing record is found.
- Marks `preexisting_dns` as `true` if a record is found.

### `cleanup_leases`
**Purpose:** Remove stale entries from the database and DDNS.

**Command:**
```bash
./ahv_ipam_ddns.sh cleanup_leases
```

**Behavior:**
- Deletes database entries older than the configured timeout.
- Removes corresponding DNS records using `nsupdate`.

### `reset_db`
**Purpose:** Clear all entries from the database lease table.

**Command:**
```bash
./ahv_ipam_ddns.sh reset_db
```

**Behavior:**
- Removes all entries from the PostgreSQL `leases` table.

### `prune_db`
**Purpose:** Remove specific IP addresses or hostnames from the database and DDNS.

**Command:**
```bash
./ahv_ipam_ddns.sh prune_db <ip_or_hostname_1> [<ip_or_hostname_2> ...]
```

**Behavior:**
- Deletes specified entries from the database.
- Removes corresponding DNS records using `nsupdate`.

## Notes and Limitations
- **Basic VLANs Only:** This version supports only Nutanix Basic VLANs. Network Controller VLAN support will be added in a future release.
- **Vault Requirement:** The script relies on HashiCorp Vault for securely storing secrets. Ensure Vault is set up and accessible.

This script has been tested in my personal Nutanix AHV lab environment and is provided as-is. Users are encouraged to thoroughly review, test, and adapt it to their specific needs before deploying in production. Contributions and testing in diverse environments are welcome! If you encounter issues or have suggestions, please open an issue on GitHub.

## License
This project is licensed under the Apache License 2.0. See the LICENSE file for details.




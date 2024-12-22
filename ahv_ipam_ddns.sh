#!/bin/bash

postgres_host="10.1.150.101"
ahv_ipam_db="ahv_ipam_db"

log_debug() {
    if [[ "$DEBUG_ENABLED" == "true" ]]; then
        echo "[DEBUG] $1"
    fi
}

load_config() {
    local config_file="ahv_ipam_ddns.json"

    if [[ ! -f "$config_file" ]]; then
        echo "Error: Configuration file '$config_file' not found."
        exit 1
    fi

    export DNS_IP_ADDRESS=$(jq -r '.dns_ip_address // empty' "$config_file")
    export DOMAIN_NAME=$(jq -r '.domain_name // empty' "$config_file")
    export NUTANIX_POLLING_INTERVAL=$(jq -r '.nutanix_polling_interval // 5' "$config_file")
    export STALE_ENTRY_TIMEOUT=$(jq -r '.stale_entry_timeout // 300' "$config_file")
    export HOSTNAME_SUBSTITUTION_FILE=$(jq -r '.hostname_substitution_file // "ddns_hostnames.csv"' "$config_file")
    export DEBUG_ENABLED=$(jq -r '.debug_enabled // false' "$config_file")
    export POSTGRES_HOST=$(jq -r '.postgres_host // empty' "$config_file")
    export AHV_IPAM_DB=$(jq -r '.ahv_ipam_db // empty' "$config_file")

    echo "Configuration loaded successfully."
    if [[ "$DEBUG_ENABLED" == "true" ]]; then
        echo "DNS_IP_ADDRESS: $DNS_IP_ADDRESS"
        echo "DOMAIN_NAME: $DOMAIN_NAME"
        echo "NUTANIX_POLLING_INTERVAL: $NUTANIX_POLLING_INTERVAL"
        echo "STALE_ENTRY_TIMEOUT: $STALE_ENTRY_TIMEOUT"
        echo "HOSTNAME_SUBSTITUTION_FILE: $HOSTNAME_SUBSTITUTION_FILE"
        echo "POSTGRES_HOST: $POSTGRES_HOST"
        echo "AHV_IPAM_DB: $AHV_IPAM_DB"
        echo "DEBUG_ENABLED: $DEBUG_ENABLED"
    fi
}

# Function to print usage
function usage() {
    echo "Usage: $0 <command>"
    echo "Commands:"
    echo "  create_db          Create the database and required tables."
    echo "  save_credentials   Save Prism Central credentials to Vault."
    echo "  get_leases         Fetch leases from Nutanix Prism Central and update the database."
    echo "  show_leases        Display all active leases in the database."
    echo "  cleanup_leases     Prune leases having exceeded TTL from database."
    echo "  update_ddns        Update DDNS with AHV lease database."
    echo "  setup_cron         Automate updates based on a polling interval."
    exit 1
}

store_in_vault() {
    local key=$1
    local value=$2
    echo "Storing $key in Vault..."
    vault kv put "$key" value="$value" > /dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Failed to store $key in Vault."
        exit 1
    fi
    echo "$key stored in Vault successfully."
}

# Function to test connection to Vault
function test_vault_connection() {
    echo "Testing connection to Vault..."
    vault status > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: Unable to connect to Vault. Ensure Vault is running and accessible."
        exit 1
    fi
    echo "Vault connection successful."
}

# Function to retrieve or set Vault secret
get_or_set_vault_password() {
    local vault_path="secret/ipa/psql/ahv_admin"
    >&2 echo "Checking Vault for $vault_path..." # Send this message to stderr
    local password=$(vault kv get -field=password "$vault_path" 2>/dev/null || true)

    if [ -z "$password" ]; then
        >&2 echo "Password not found in Vault. Please create a new password."
        read -s -p "Enter a password for the postgres 'leases' table user ahv_admin: " password
        echo
        store_in_vault "$vault_path" "$password"
        >&2 echo "Password set in Vault."
    else
        >&2 echo "Password retrieved from Vault."
    fi

    echo "$password" # Return only the password to stdout
}

# Function to test PostgreSQL connection
function test_psql_connection() {
    local host=$1
    local db=$2
    local user=$3
    local password=$4

    echo "Testing PostgreSQL connection..."
    export PGPASSWORD="$password"
    psql -U "$user" -h "$host" -d "$db" -c '\\q' 2>/dev/null
    if [ $? -ne 0 ];then
        echo "Error: Unable to connect to PostgreSQL with provided credentials."
        exit 1
    fi
    echo "PostgreSQL connection successful."
}

# Function to check if the database exists
check_or_create_database() {
    local host=$1
    local db=$2
    local user=$3
    local password=$4

    echo "Creating database '$db' if it does not exist..."
    export PGPASSWORD="$password"

    psql -U "$user" -h "$host" -d postgres -c "CREATE DATABASE $db;" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Database '$db' already exists or could not be created."
    else
        echo "Database '$db' created successfully."
    fi

    echo "Ensuring the 'leases' table exists in database '$db'..."
    local table_exists=$(psql -U "$user" -h "$host" -d "$db" -tAc "SELECT 1 FROM information_schema.tables WHERE table_name='leases';")
    if [ "$table_exists" == "1" ]; then
        echo "'leases' table already exists in database '$db'."
    else
        echo "'leases' table does not exist. Creating..."
        psql -U "$user" -h "$host" -d "$db" -c "
            CREATE TABLE leases (
                ip_address VARCHAR(45) NOT NULL,
                vm_name VARCHAR(255),
                hostname VARCHAR(255),
                mac_address VARCHAR(17),
                vlan_uuid VARCHAR(36),
                vlan_name VARCHAR(255),
                vlan_tag INTEGER DEFAULT NULL,
                last_updated TIMESTAMP DEFAULT NOW(),
                PRIMARY KEY (ip_address)
            );
        "
        echo "'leases' table created successfully."
    fi
}

# Function to query the database as an indicator
function display_database_indicator() {
    local host=$1
    local db=$2
    local user=$3
    local password=$4

    echo "Querying database '$db' to verify..."
    PGPASSWORD="$password" psql -U "$user" -h "$host" -d "$db" -c "SELECT current_database();" | grep "$db"
    echo "Database '$db' is ready and accessible."
}

save_credentials() {
    local prism_central_ip=$1
    local username=$2
    local password=$3

    # Validate input arguments
    if [ -z "$prism_central_ip" ] || [ -z "$username" ] || [ -z "$password" ]; then
        echo "Error: Missing required arguments."
        echo "Usage: save_credentials <prism_central_ip> <username> <password>"
        return 1
    fi

    # Generate Base64-encoded credentials
    local encoded_credentials=$(echo -n "${username}:${password}" | base64)

    # Test the credentials against Nutanix API
    echo "Testing credentials against Nutanix Prism Central at $prism_central_ip..."
    local response=$(curl -s -o /tmp/curl_output -w "%{http_code}" -X POST \
        "https://$prism_central_ip:9440/api/nutanix/v3/vms/list" \
        -H "Authorization: Basic $encoded_credentials" \
        -H "Content-Type: application/json" \
        -d '{"kind": "vm"}' \
        -k)

    if [ "$response" -ne 200 ]; then
        echo "Error: Invalid credentials or connection issue. HTTP Status: $response"
        return 1
    fi

    # Store the encoded credentials and Prism Central IP/URL in Vault
    store_in_vault "secret/nutanix/encoded_credentials" "$encoded_credentials"
    store_in_vault "secret/nutanix/prism_central_ip" "$prism_central_ip"
}

get_ipam_vlans() {
    echo "Fetching IPAM-managed VLANs..."
    local response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
        "https://$prism_central_ip:9440/api/nutanix/v3/subnets/list" \
        -H "Authorization: Basic $encoded_credentials" \
        -H "Content-Type: application/json" \
        -d '{"kind": "subnet"}' -k)

    local http_body=$(echo "$response" | sed -e 's/HTTP_STATUS:.*//g')
    local http_status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')

    log_debug "Debug: http_body: $http_body"
    if [ "$http_status" -ne 200 ]; then
        echo "Error: Failed to fetch VLAN data. HTTP Status: $http_status"
        return 1
    fi

    # Filter valid VLANs and ensure no duplicates
    readarray -t ipam_vlans < <(echo "$http_body" | jq -r '.entities[] | select(.spec.resources.ip_config.pool_list and .status.resources.vlan_id != null and .status.resources.vlan_id != "null") | .metadata.uuid' | sort -u)
    readarray -t ipam_vlan_names < <(echo "$http_body" | jq -r '.entities[] | select(.spec.resources.ip_config.pool_list and .status.resources.vlan_id != null and .status.resources.vlan_id != "null") | .status.name' | sort -u)
    readarray -t ipam_vlan_tags < <(echo "$http_body" | jq -r '.entities[] | select(.spec.resources.ip_config.pool_list and .status.resources.vlan_id != null and .status.resources.vlan_id != "null") | .status.resources.vlan_id' | sort -u)

    log_debug "Debug: Unique IPAM VLAN UUIDs: ${ipam_vlans[*]}"
    log_debug "Debug: Unique IPAM VLAN Names: ${ipam_vlan_names[*]}"
    log_debug "Debug: Unique IPAM VLAN Tags: ${ipam_vlan_tags[*]}"
}

show_leases() {
    export PGPASSWORD="$(vault kv get -field=password secret/ipa/psql/ahv_admin)"
    psql -U ahv_admin -h "$postgres_host" -d "$ahv_ipam_db" -c "SELECT * FROM leases;"
}

cleanup_leases() {
    echo "Cleaning up stale entries in the database..."
    export PGPASSWORD="$(vault kv get -field=password secret/ipa/psql/ahv_admin)"
    psql -U ahv_admin -h "$postgres_host" -d "$ahv_ipam_db" -c "
        DELETE FROM leases WHERE last_updated < NOW() - INTERVAL '${STALE_ENTRY_TIMEOUT} seconds';
    "
    echo "Stale entries removed."
}

get_leases() {
    echo "Starting get_leases..."

    local prism_central_ip
    local encoded_credentials

    prism_central_ip=$(vault kv get -field=value "secret/nutanix/prism_central_ip" 2>/dev/null)
    if [ -z "$prism_central_ip" ]; then
        echo "Error: Prism Central IP not found in Vault. Run 'save_credentials' first."
        return 1
    fi

    encoded_credentials=$(vault kv get -field=value "secret/nutanix/encoded_credentials" 2>/dev/null)
    if [ -z "$encoded_credentials" ]; then
        echo "Error: Encoded credentials not found in Vault. Run 'save_credentials' first."
        return 1
    fi

    echo "Fetching IPAM-managed VLANs..."
    get_ipam_vlans
    if [ $? -ne 0 ]; then
        echo "Error: Failed to fetch IPAM-managed VLANs."
        return 1
    fi

    # Load preferred hostnames from CSV
    declare -A hostname_map
    log_debug "Debug: Loading hostname map from ${HOSTNAME_SUBSTITUTION_FILE}"

    while IFS=',' read -r normalized_hostname preferred_hostname || [ -n "$normalized_hostname" ]; do
        # Skip empty lines or lines missing required fields
        if [[ -z "$normalized_hostname" || -z "$preferred_hostname" ]]; then
            echo "Error: Malformed line in ${HOSTNAME_SUBSTITUTION_FILE}: '$normalized_hostname,$preferred_hostname'. Skipping."
            continue
        fi

        # Log the mapping
        log_debug "Debug: Mapping $normalized_hostname -> $preferred_hostname"

        # Add to the hostname map
        hostname_map["$normalized_hostname"]="$preferred_hostname"
    done < ${HOSTNAME_SUBSTITUTION_FILE}

    log_debug "Debug: Loaded hostname_map keys: ${!hostname_map[*]}"

    echo "Fetching VM lease data from Nutanix Prism Central at $prism_central_ip..."
    local response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
        "https://$prism_central_ip:9440/api/nutanix/v3/vms/list" \
        -H "Authorization: Basic $encoded_credentials" \
        -H "Content-Type: application/json" \
        -d '{"kind": "vm"}' -k)

    local http_body=$(echo "$response" | sed -e 's/HTTP_STATUS:.*//g')
    local http_status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')

    if [ "$http_status" -ne 200 ]; then
        echo "Error: Failed to fetch VM lease data. HTTP Status: $http_status"
        echo "HTTP Body: $http_body"
        return 1
    fi

    echo "Parsing VM lease data..."
    echo "$http_body" | jq -c '.entities[]' | while read -r entity; do
        local vm_name=$(echo "$entity" | jq -r '.status.name // empty')
        local nic_list=$(echo "$entity" | jq -c '.status.resources.nic_list[]?')

        echo "$nic_list" | jq -c 'select(.ip_endpoint_list[]?.ip_type == "DHCP")' | while read -r nic; do
            local ip_address=$(echo "$nic" | jq -r '.ip_endpoint_list[]?.ip // empty')
            local mac_address=$(echo "$nic" | jq -r '.mac_address // empty')
            local vlan_uuid=$(echo "$nic" | jq -r '.subnet_reference.uuid // empty')

            log_debug "Debug: Processing VM $vm_name with IP $ip_address, VLAN UUID $vlan_uuid"

            # Match VLAN UUID to IPAM-managed VLANs
            local vlan_name=""
            local vlan_tag=""
            for index in "${!ipam_vlans[@]}"; do
                if [[ "${ipam_vlans[$index]}" == "$vlan_uuid" ]]; then
                    vlan_name="${ipam_vlan_names[$index]}"
                    vlan_tag="${ipam_vlan_tags[$index]}"
                    log_debug "Debug: Matched VLAN UUID $vlan_uuid to VLAN Name $vlan_name and Tag $vlan_tag."
                    break
                fi
            done

            if [[ -z "$vlan_name" || -z "$vlan_tag" ]]; then
                log_debug "Debug: Skipping VLAN UUID $vlan_uuid. No match found in IPAM-managed VLANs."
                continue
            fi

            # Generate normalized hostname
            local normalized_hostname=$(echo "$vm_name" | tr -cd '[:alnum:].-' | tr '[:upper:]' '[:lower:]')
            log_debug "Debug: Normalized hostname before substitution: $normalized_hostname"

            # Debug: Validate array access
            if [[ -z "$normalized_hostname" ]]; then
                log_debug "Debug: Skipping entry due to empty normalized hostname."
                continue
            fi

            # Substitute with preferred hostname if available
            if [[ -v "hostname_map[$normalized_hostname]" ]]; then
                local hostname="${hostname_map[$normalized_hostname]}"
                log_debug "Debug: Substituted hostname: $hostname"
            else
                local hostname="$normalized_hostname"
                log_debug "Debug: Using normalized hostname: $hostname"
            fi

            export PGPASSWORD="$(vault kv get -field=password secret/ipa/psql/ahv_admin)"

            psql -U ahv_admin -h "$postgres_host" -d "$ahv_ipam_db" -c "
                INSERT INTO leases (ip_address, vm_name, hostname, mac_address, vlan_uuid, vlan_name, vlan_tag, last_updated)
                VALUES ('$ip_address', '$vm_name', '$hostname', '$mac_address', '$vlan_uuid', '$vlan_name', $vlan_tag, NOW())
                ON CONFLICT (ip_address) DO UPDATE
                SET vm_name = EXCLUDED.vm_name,
                    hostname = EXCLUDED.hostname,
                    mac_address = EXCLUDED.mac_address,
                    vlan_uuid = EXCLUDED.vlan_uuid,
                    vlan_name = EXCLUDED.vlan_name,
                    vlan_tag = EXCLUDED.vlan_tag,
                    last_updated = NOW();
            "
            if [ $? -ne 0 ]; then
                echo "Error: Failed to insert lease for VM $vm_name ($ip_address)."
            fi
        done
    done
    echo "VM lease data processing complete."
}

update_ddns() {
    echo "Updating DDNS with entries from the database..."

    # Define required variables
    local tsig_key
    tsig_key="$(vault kv get -field=tsig_key secret/ipa/dns)"
    local dns_server=${DNS_IP_ADDRESS}
    local domain="${DOMAIN_NAME}"
    local ttl=${STALE_ENTRY_TIMEOUT}

    log_debug "tsig_key retrieved successfully."

    # Check if TSIG key is retrieved successfully
    if [[ -z "$tsig_key" ]]; then
        echo "Error: TSIG key not found or could not be retrieved from Vault."
        return 1
    fi

    # Write TSIG key to a temporary file
    local tsig_key_file="/tmp/ipa_ddns_key.key"
    cat > "$tsig_key_file" <<EOF
key "ipa_ddns_key" {
    algorithm hmac-sha256;
    secret "$tsig_key";
};
EOF

    # Ensure the TSIG key file is cleaned up on exit
    trap 'rm -f "$tsig_key_file"' EXIT

    # Query the leases database
    export PGPASSWORD="$(vault kv get -field=password secret/ipa/psql/ahv_admin)"
    local query="SELECT ip_address, hostname FROM leases;"
    local result=$(psql -U ahv_admin -h "$postgres_host" -d "$ahv_ipam_db" -t -A -F, -c "$query")

    if [[ -z "$result" ]]; then
        echo "No entries found in the database to update DDNS."
        return 0
    fi

    echo "$result" | while IFS=',' read -r ip_address hostname; do
        echo "Processing $hostname ($ip_address)..."

        # Create nsupdate commands
        local nsupdate_file="/tmp/nsupdate_${hostname}.txt"
        cat > "$nsupdate_file" <<EOF
server $dns_server
zone $domain
update delete $hostname.$domain A
update add $hostname.$domain $ttl A $ip_address
send
EOF

        # Debug: Print nsupdate file content
        if [[ "$DEBUG_ENABLED" == "true" ]]; then
            echo "[DEBUG] nsupdate file content for $hostname:"
            cat "$nsupdate_file"
        fi

        # Execute nsupdate using the TSIG key file
        nsupdate -k "$tsig_key_file" "$nsupdate_file"
        if [ $? -eq 0 ]; then
            echo "Successfully updated DDNS for $hostname ($ip_address)."
        else
            echo "Error: Failed to update DDNS for $hostname ($ip_address)."
        fi

        # Clean up nsupdate file
        rm -f "$nsupdate_file"
    done

    echo "DDNS update process complete."
}
setup_cron() {
    local cron_job="*/$NUTANIX_POLLING_INTERVAL * * * * $(realpath "$0") get_leases >> /var/log/ahv_ipam.log 2>&1; $(realpath "$0") update_ddns >> /var/log/ahv_ipam.log 2>&1; $(realpath "$0") cleanup_leases >> /var/log/ahv_ipam.log 2>&1"

    echo "Adding the following cron job:"
    echo "$cron_job"
    
    (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
    echo "Cron job added successfully."
}

load_config

case "$1" in
    create_db)
        test_vault_connection
        ahv_admin_password=$(get_or_set_vault_password)
        check_or_create_database "$postgres_host" "$ahv_ipam_db" "ahv_admin" "$ahv_admin_password"
        ;;
    save_credentials)
        save_credentials "$2" "$3" "$4"
        ;;
    get_leases)
        get_leases
        ;;
    show_leases)
        show_leases
        ;;
    cleanup_leases)
        cleanup_leases
        ;;
    update_ddns)
	update_ddns
	;;
    setup_cron)
	setup_cron
	;;
    *)
        usage
        ;;
esac


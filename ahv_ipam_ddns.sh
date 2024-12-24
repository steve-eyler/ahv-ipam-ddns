#!/bin/bash

###############################################################################
#   Level 0 => minimal user-level messages only.
#   Level 1 => basic debug statements.
#   Level 2 => includes detailed debug + full JSON bodies.
###############################################################################
log_debug() {
    local debug_level="$1"
    local message="$2"

    # If debug_level=0, rely on normal echo statements for most user feedback
    # This function is only for debug. So skip if LOG_LEVEL < debug_level.
    if [[ "$LOG_LEVEL" -ge "$debug_level" ]]; then
        echo "[DEBUG] $message"
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
    export LOG_LEVEL=$(jq -r '.log_level // 0' "$config_file")
    export POSTGRES_HOST=$(jq -r '.postgres_host // empty' "$config_file")
    export AHV_IPAM_DB=$(jq -r '.ahv_ipam_db // empty' "$config_file")

    # For log_level=0, only minimal output.
    if [ "$LOG_LEVEL" -gt 0 ]; then
        echo "Configuration loaded successfully."
        echo "DNS_IP_ADDRESS: $DNS_IP_ADDRESS"
        echo "DOMAIN_NAME: $DOMAIN_NAME"
        echo "NUTANIX_POLLING_INTERVAL: $NUTANIX_POLLING_INTERVAL"
        echo "STALE_ENTRY_TIMEOUT: $STALE_ENTRY_TIMEOUT"
        echo "HOSTNAME_SUBSTITUTION_FILE: $HOSTNAME_SUBSTITUTION_FILE"
        echo "POSTGRES_HOST: $POSTGRES_HOST"
        echo "AHV_IPAM_DB: $AHV_IPAM_DB"
        echo "LOG_LEVEL: $LOG_LEVEL"
    fi
}

function usage() {
    echo "Usage: $0 <command>"
    echo "Commands:"
    echo "  create_db          Create the database and required tables."
    echo "  save_credentials   Save Prism Central credentials to Vault."
    echo "  get_leases         Fetch leases from Nutanix Prism Central and update the database."
    echo "  show_leases        Display all active leases in the database."
    echo "  cleanup_leases     Prune leases older than the TTL from database."
    echo "  update_ddns        Update DDNS with AHV lease database."
    echo "  setup_cron         Automate updates based on a polling interval."
    echo "  get_names          List VMs + normalized name + substitution if found."
    echo "  reset_db           Clear out all entries from 'leases' table."
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

# Test Vault connection
function test_vault_connection() {
    echo "Testing connection to Vault..."
    vault status > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: Unable to connect to Vault. Ensure Vault is running and accessible."
        exit 1
    fi
    echo "Vault connection successful."
}

# Retrieve or set Vault password
get_or_set_vault_password() {
    local vault_path="secret/ipa/psql/ahv_admin"
    >&2 echo "Checking Vault for $vault_path..."
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

    echo "$password"
}

# Test PostgreSQL connection
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

# Check or create DB/tables
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
    local table_exists=$(psql -U "$user" -h "$host" -d "$db" -tAc \
      "SELECT 1 FROM information_schema.tables WHERE table_name='leases';")

    if [ "$table_exists" == "1" ]; then
        echo "'leases' table already exists in database '$db'."
        # Now ensure preexisting_dns column:
        psql -U "$user" -h "$host" -d "$db" -c "
            ALTER TABLE leases
            ADD COLUMN IF NOT EXISTS preexisting_dns BOOLEAN DEFAULT false;
        " >/dev/null 2>&1
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
                preexisting_dns BOOLEAN DEFAULT false,
                PRIMARY KEY (ip_address)
            );
        "
        echo "'leases' table created successfully."
    fi
}

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

    if [ -z "$prism_central_ip" ] || [ -z "$username" ] || [ -z "$password" ]; then
        echo "Error: Missing required arguments."
        echo "Usage: save_credentials <prism_central_ip> <username> <password>"
        return 1
    fi

    local encoded_credentials
    encoded_credentials=$(echo -n "${username}:${password}" | base64)

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

    store_in_vault "secret/nutanix/encoded_credentials" "$encoded_credentials"
    store_in_vault "secret/nutanix/prism_central_ip" "$prism_central_ip"
}

declare -A ipam_name_by_uuid
declare -A ipam_tag_by_uuid

get_ipam_vlans() {
    ### REMOVED the second echo line to avoid duplication. ###

    local offset=0
    local page_size=20
    local total_matches=1

    ipam_name_by_uuid=()
    ipam_tag_by_uuid=()

    while [ "$offset" -lt "$total_matches" ]; do
        local payload='{"kind":"subnet","offset":'"$offset"',"length":'"$page_size"'}'
        log_debug 1 "Calling subnets/list with offset=$offset, length=$page_size"

        local response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
            "https://$prism_central_ip:9440/api/nutanix/v3/subnets/list" \
            -H "Authorization: Basic $encoded_credentials" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            -k)

        local http_body=$(echo "$response" | sed -e 's/HTTP_STATUS:.*//g')
        local http_status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')

        log_debug 1 "HTTP status from subnets/list: $http_status"
        if [ "$http_status" -ne 200 ]; then
            echo "Error: subnets/list call failed. HTTP $http_status"
            return 1
        fi

        if [ "$LOG_LEVEL" -eq 2 ]; then
            log_debug 2 "Full subnets/list response: $http_body"
        fi

        local this_length=$(echo "$http_body" | jq '.metadata.length // 0')
        total_matches=$(echo "$http_body" | jq '.metadata.total_matches // 0')
        local this_offset=$(echo "$http_body" | jq '.metadata.offset // 0')
        log_debug 1 "metadata.offset=$this_offset, metadata.length=$this_length, total_matches=$total_matches"

        local entity_count
        entity_count=$(echo "$http_body" | jq '.entities | length')
        for i in $(seq 0 $((entity_count-1))); do
            local has_pool=$(echo "$http_body" | jq -r ".entities[$i].spec.resources.ip_config.pool_list // empty")
            local vlan_id=$(echo "$http_body" | jq -r ".entities[$i].status.resources.vlan_id // empty")
            if [[ -n "$has_pool" && -n "$vlan_id" && "$vlan_id" != "null" ]]; then
                local suuid=$(echo "$http_body" | jq -r ".entities[$i].metadata.uuid")
                local sname=$(echo "$http_body" | jq -r ".entities[$i].status.name")
                local stag=$(echo "$http_body" | jq -r ".entities[$i].status.resources.vlan_id")

                ipam_name_by_uuid["$suuid"]="$sname"
                ipam_tag_by_uuid["$suuid"]="$stag"

                log_debug 1 "Captured IPAM subnet: UUID=$suuid, Name=$sname, Tag=$stag"
            fi
        done

        offset=$(( offset + this_length ))
        if [ "$this_length" -eq 0 ]; then
            log_debug 1 "No more subnets returned; ending pagination."
            break
        fi
    done

    if [ "$LOG_LEVEL" -ge 1 ]; then
        log_debug 1 "Finished collecting IPAM VLAN data. Subnets found:"
        for uuid in "${!ipam_name_by_uuid[@]}"; do
            log_debug 1 "  VLAN UUID=$uuid => '${ipam_name_by_uuid[$uuid]}' (tag=${ipam_tag_by_uuid[$uuid]})"
        done
    fi
}

show_leases() {
    export PGPASSWORD="$(vault kv get -field=password secret/ipa/psql/ahv_admin)"
    psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "SELECT * FROM leases;"
}

# cleanup_leases():
#   1) Do not remove if preexisting_dns=true
#   2) Remove from DNS (nsupdate) and from DB if older than STALE_ENTRY_TIMEOUT
cleanup_leases() {
    export PGPASSWORD="$(vault kv get -field=password secret/ipa/psql/ahv_admin)"

    local tsig_key
    tsig_key="$(vault kv get -field=tsig_key secret/ipa/dns)"
    local dns_server="${DNS_IP_ADDRESS}"
    local domain="${DOMAIN_NAME}"
    local ttl="${STALE_ENTRY_TIMEOUT}"

    local tsig_key_file="/tmp/ipa_ddns_key.key"
    cat > "$tsig_key_file" <<EOF
key "ipa_ddns_key" {
    algorithm hmac-sha256;
    secret "$tsig_key";
};
EOF
    trap 'rm -f "$tsig_key_file"' EXIT

    # Return stale entries while excluding preexisting_dns
    local stale_query="
        DELETE FROM leases
         WHERE preexisting_dns = false
           AND last_updated < NOW() - INTERVAL '${STALE_ENTRY_TIMEOUT} seconds'
        RETURNING ip_address, hostname;
    "

    local stale_result
    stale_result="$(psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -t -A -F ',' -c "$stale_query")"

    if [[ -z "$stale_result" ]]; then
        [ "$LOG_LEVEL" -eq 0 ] || echo "No stale entries found to remove."
        return 0
    fi

    echo "$stale_result" | while IFS=',' read -r ip_address hostname; do
        [[ -z "$hostname" ]] && continue
        local fqdn="$hostname.$domain"

        # Build nsupdate file
        local nsupdate_file="/tmp/nsupdate_del_${hostname}.txt"
        cat > "$nsupdate_file" <<EOF
server $dns_server
zone $domain
update delete $fqdn A
send
EOF

        nsupdate -k "$tsig_key_file" "$nsupdate_file"
        if [ $? -eq 0 ]; then
            echo "Removed stale DNS entry for $fqdn ($ip_address)."
        else
            echo "Error removing DNS record for $fqdn ($ip_address)."
        fi

        rm -f "$nsupdate_file"
    done

    [ "$LOG_LEVEL" -eq 0 ] || echo "Stale entries removed from DB and DNS."
}

update_ddns() {
    echo "Updating DDNS with entries from the database..."

    local tsig_key
    tsig_key="$(vault kv get -field=tsig_key secret/ipa/dns)"
    local dns_server=${DNS_IP_ADDRESS}
    local domain="${DOMAIN_NAME}"
    local ttl=${STALE_ENTRY_TIMEOUT}

    if [[ -z "$tsig_key" ]]; then
        echo "Error: TSIG key not found or could not be retrieved from Vault."
        return 1
    fi

    local tsig_key_file="/tmp/ipa_ddns_key.key"
    cat > "$tsig_key_file" <<EOF
key "ipa_ddns_key" {
    algorithm hmac-sha256;
    secret "$tsig_key";
};
EOF

    trap 'rm -f "$tsig_key_file"' EXIT

    export PGPASSWORD="$(vault kv get -field=password secret/ipa/psql/ahv_admin)"
    local query="SELECT ip_address, hostname, preexisting_dns FROM leases;"
    local result
    result="$(psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -t -A -F '|' -c "$query")"

    if [[ -z "$result" ]]; then
        echo "No entries found in the database to update DDNS."
        return 0
    fi

    while IFS='|' read -r ip_address hostname preexisting; do
        if [[ -z "$hostname" ]]; then
            continue
        fi

        local fqdn="${hostname}.${domain}"

        echo "Processing $fqdn ($ip_address)..."

        # If preexisting_dns is already true, skip
        if [[ "$preexisting" == "t" ]]; then
            echo "Skipping $fqdn since it is marked as preexisting_dns."
            continue
        fi

        # 1) Forward check
        echo "DEBUG: Checking forward DNS with: nslookup \"$fqdn\" \"$dns_server\""
        nslookup "$fqdn" "$dns_server" >/dev/null 2>&1
        local forward_rc=$?

        # 2) Reverse check
        echo "DEBUG: Checking reverse DNS with: nslookup \"$ip_address\" \"$dns_server\""
        nslookup "$ip_address" "$dns_server" >/dev/null 2>&1
        local reverse_rc=$?

        echo "DEBUG: forward_rc=$forward_rc, reverse_rc=$reverse_rc"

        if [[ $forward_rc -eq 0 || $reverse_rc -eq 0 ]]; then
            # Mark as preexisting
            psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "
                UPDATE leases
                SET preexisting_dns = true
                WHERE ip_address = '$ip_address';
            " >/dev/null 2>&1

            echo "DNS record found for $fqdn or $ip_address. Marking preexisting_dns=true; skipping update."
            continue
        fi

        # Otherwise, do normal "delete/add"
        local nsupdate_file="/tmp/nsupdate_${hostname}.txt"
        cat > "$nsupdate_file" <<EOF
server $dns_server
zone $domain
update delete $fqdn A
update add $fqdn $ttl A $ip_address
send
EOF

        nsupdate -k "$tsig_key_file" "$nsupdate_file"
        if [ $? -eq 0 ]; then
            echo "Successfully updated DDNS for $fqdn ($ip_address)."
        else
            echo "Error: Failed to update DDNS for $fqdn ($ip_address)."
        fi

        rm -f "$nsupdate_file"
    done <<< "$result"

    echo "DDNS update process complete."
}

# Clear all entries from the database lease table. Does not affect DDNS.
reset_db() {
    export PGPASSWORD="$(vault kv get -field=password secret/ipa/psql/ahv_admin)"
    psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "
        DELETE FROM leases;
    " >/dev/null 2>&1

    if [ "$LOG_LEVEL" -eq 0 ]; then
        echo "reset_db completed."
    else
        echo "reset_db completed. All entries cleared from leases table."
    fi
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

    echo "Fetching IPAM-managed VLANs from Nutanix Prism Central..."
    get_ipam_vlans
    if [ $? -ne 0 ]; then
        echo "Error: Failed to fetch IPAM-managed VLANs."
        return 1
    fi

    # Load preferred hostnames from CSV
    declare -A hostname_map
    log_debug 1 "Loading hostname map from ${HOSTNAME_SUBSTITUTION_FILE}"

    while IFS=',' read -r normalized_hostname preferred_hostname || [ -n "$normalized_hostname" ]; do
        if [[ -z "$normalized_hostname" || -z "$preferred_hostname" ]]; then
            echo "Error: Malformed line in ${HOSTNAME_SUBSTITUTION_FILE}: '$normalized_hostname,$preferred_hostname'. Skipping."
            continue
        fi
        log_debug 1 "Mapping $normalized_hostname -> $preferred_hostname"
        hostname_map["$normalized_hostname"]="$preferred_hostname"
    done < "${HOSTNAME_SUBSTITUTION_FILE}"

    log_debug 1 "Loaded hostname_map keys: ${!hostname_map[*]}"

    echo "Fetching VM lease data from Nutanix Prism Central at $prism_central_ip..."

    local offset=0
    local page_size=20
    local total_vm_matches=1
    local lease_changes=0

    while [ "$offset" -lt "$total_vm_matches" ]; do
        local vm_payload='{"kind":"vm","offset":'"$offset"',"length":'"$page_size"'}'
        log_debug 1 "Calling vms/list with offset=$offset, length=$page_size"

        local response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
            "https://$prism_central_ip:9440/api/nutanix/v3/vms/list" \
            -H "Authorization: Basic $encoded_credentials" \
            -H "Content-Type: application/json" \
            -d "$vm_payload" \
            -k)

        local http_body=$(echo "$response" | sed -e 's/HTTP_STATUS:.*//g')
        local http_status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')

        log_debug 1 "HTTP status from vms/list: $http_status"
        if [ "$http_status" -ne 200 ]; then
            echo "Error: Failed to fetch VM lease data. HTTP Status: $http_status"
            echo "HTTP Body: $http_body"
            return 1
        fi

        if [ "$LOG_LEVEL" -eq 2 ]; then
            log_debug 2 "Full vms/list response: $http_body"
        fi

        local this_length
        this_length=$(echo "$http_body" | jq '.metadata.length // 0')
        total_vm_matches=$(echo "$http_body" | jq '.metadata.total_matches // 0')
        local this_offset
        this_offset=$(echo "$http_body" | jq '.metadata.offset // 0')
        log_debug 1 "VM metadata.offset=$this_offset, metadata.length=$this_length, total_matches=$total_vm_matches"

        # ------------------------
        # 1) Entities loop
        while read -r entity; do
            local vm_name
            vm_name=$(echo "$entity" | jq -r '.status.name // empty')
            log_debug 1 "Processing VM entity with name: $vm_name"

            # 2) NIC loop
            # We'll store the NIC array in a variable, then process-substitute.
            local nic_list
            nic_list=$(echo "$entity" | jq -c '.status.resources.nic_list[]?')

            while read -r nic; do
                # 3) IP Endpoint loop
                local ip_endpoint_list
                ip_endpoint_list=$(echo "$nic" | jq -c '.ip_endpoint_list[]?')

                while read -r ip_ep; do
                    local ip_type
                    ip_type=$(echo "$ip_ep" | jq -r '.ip_type')
                    local ip_address
                    ip_address=$(echo "$ip_ep" | jq -r '.ip')
                    local mac_address
                    mac_address=$(echo "$nic" | jq -r '.mac_address // empty')
                    local vlan_uuid
                    vlan_uuid=$(echo "$nic" | jq -r '.subnet_reference.uuid // empty')

                    if [[ "$ip_type" == "DHCP" || "$ip_type" == "LEARNED" \
                          || "$ip_type" == "ASSIGNED" || "$ip_type" == "STATIC" \
                          || "$ip_type" == "null" ]]; then

                        log_debug 1 "VM $vm_name has IP $ip_address ($ip_type), VLAN UUID $vlan_uuid"
                        local vlan_name="${ipam_name_by_uuid[$vlan_uuid]}"
                        local vlan_tag="${ipam_tag_by_uuid[$vlan_uuid]}"

                        if [[ -z "$vlan_name" || -z "$vlan_tag" ]]; then
                            log_debug 1 "Skipping IP $ip_address on $vm_name: VLAN $vlan_uuid not in IPAM-managed list."
                            continue
                        fi

                        local normalized_hostname
                        normalized_hostname=$(echo "$vm_name" | tr -cd '[:alnum:].-' | tr '[:upper:]' '[:lower:]')
                        if [[ -z "$normalized_hostname" ]]; then
                            log_debug 1 "Skipping empty normalized hostname for $vm_name ($ip_address)."
                            continue
                        fi

                        local final_hostname="${hostname_map[$normalized_hostname]:-$normalized_hostname}"
                        if [[ "$final_hostname" != "$normalized_hostname" ]]; then
                            log_debug 1 "Substituted hostname: $normalized_hostname -> $final_hostname"
                        else
                            log_debug 1 "Using normalized hostname: $final_hostname"
                        fi

                        export PGPASSWORD="$(vault kv get -field=password secret/ipa/psql/ahv_admin)"
                        psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "
                            INSERT INTO leases (
                                ip_address, vm_name, hostname, mac_address, vlan_uuid,
                                vlan_name, vlan_tag, last_updated
                            )
                            VALUES (
                                '$ip_address', '$vm_name', '$final_hostname', '$mac_address', '$vlan_uuid',
                                '$vlan_name', $vlan_tag, NOW()
                            )
                            ON CONFLICT (ip_address) DO UPDATE
                            SET vm_name = EXCLUDED.vm_name,
                                hostname = EXCLUDED.hostname,
                                mac_address = EXCLUDED.mac_address,
                                vlan_uuid = EXCLUDED.vlan_uuid,
                                vlan_name = EXCLUDED.vlan_name,
                                vlan_tag = EXCLUDED.vlan_tag,
                                last_updated = NOW();
                        " >/dev/null 2>&1

                        (( lease_changes++ ))
                    else
                        log_debug 2 "Skipping IP $ip_address (type=$ip_type) on VM $vm_name"
                    fi
                done < <( printf "%s\n" "$ip_endpoint_list" )  # <---- process-substitution
            done < <( printf "%s\n" "$nic_list" )              # <---- process-substitution
        done < <( echo "$http_body" | jq -c '.entities[]' )    # <---- process-substitution
        # ------------------------

        offset=$(( offset + this_length ))
        if [ "$this_length" -eq 0 ]; then
            log_debug 1 "No more VMs returned; ending pagination."
            break
        fi
    done

    echo "get_leases completed. $lease_changes hosts populated in lease table."
}

get_names() {
    echo "Fetching VM names from the leases database..."
    export PGPASSWORD="$(vault kv get -field=password secret/ipa/psql/ahv_admin)"

    local query="SELECT vm_name, hostname FROM leases ORDER BY vm_name;"
    local result
    result="$(psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -t -A -F '|' -c "$query")"

    if [[ -z "$result" ]]; then
        echo "No VMs found in the leases database."
        return
    fi

    while IFS='|' read -r vm_name db_hostname; do
        local normalized
        normalized="$(echo "$vm_name" | tr -cd '[:alnum:].-' | tr '[:upper:]' '[:lower:]')"

        # If normalized != db_hostname => print both, else just normalized
        if [[ "$normalized" != "$db_hostname" ]]; then
            echo "$normalized,$db_hostname"
        else
            echo "$normalized"
        fi
    done <<< "$result"
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
        check_or_create_database "$POSTGRES_HOST" "$AHV_IPAM_DB" "ahv_admin" "$ahv_admin_password"
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
    get_names)
        get_names
        ;;
    reset_db)
        reset_db
        ;;
    *)
        usage
        ;;
esac



#!/bin/bash

###############################################################################
# CONFIGURATION / PATHS
###############################################################################
config_file="/home/steve/github/ahv_ipam_ddns.json"

TOKEN_FILE="/tmp/ahv_admin-app-policy.token"
export VAULT_ADDR="https://10.1.150.103:8200"
VAULT_BIN="/usr/local/bin/vault"

###############################################################################
# LOGGING: debug-level messages
#  - LOG_LEVEL = 0 => minimal
#  - LOG_LEVEL = 1 => basic debug
#  - LOG_LEVEL = 2 => detailed + full JSON
###############################################################################
log_debug() {
    local debug_level="$1"
    local message="$2"

    if [[ "$LOG_LEVEL" -ge "$debug_level" ]]; then
        echo "[DEBUG] $message"
    fi
}

###############################################################################
# VAULT TOKEN VALIDATION
#  - Attempt to load token from $TOKEN_FILE
#  - Validate with `vault token lookup`
###############################################################################
if [ -f "$TOKEN_FILE" ] && [ -r "$TOKEN_FILE" ]; then
    export VAULT_TOKEN=$(cat "$TOKEN_FILE")

    if ${VAULT_BIN} token lookup >/dev/null 2>&1; then
        log_debug 1 "Vault token is valid."
    else
        echo "Error: The token in $TOKEN_FILE is invalid or expired."
        unset VAULT_TOKEN
        exit 1
    fi
else
    echo "Error: Token file $TOKEN_FILE does not exist or is not readable."
    unset VAULT_TOKEN
    exit 1
fi

###############################################################################
# load_config: read settings from JSON config file
###############################################################################
load_config() {
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

usage() {
    echo "Usage: $0 <command>"
    echo "Commands:"
    echo "  create_db          Create the database and required tables."
    echo "  reset_db           Clear out all entries from 'leases' table."
    echo "  prune_db           Remove specified entries from 'leases' table and from DDNS."
    echo "  save_credentials   Save Prism Central credentials to Vault."
    echo "  get_leases         Fetch leases from Nutanix Prism Central and update the database."
    echo "  show_leases        Display all active leases in the database."
    echo "  cleanup_leases     Prune leases older than the TTL from database."
    echo "  update_ddns        Update DDNS with AHV lease database."
    echo "  setup_cron         Automate updates based on a polling interval."
    echo "  show_hostnames     List VMs by normalized name + substitution hostname if found."
    exit 1
}

###############################################################################
# VAULT HELPER FUNCTIONS
###############################################################################
store_in_vault() {
    local key="$1"
    local value="$2"
    echo "Storing $key in Vault..."
    ${VAULT_BIN} kv put "$key" value="$value" >/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Failed to store $key in Vault."
        exit 1
    fi
    echo "$key stored in Vault successfully."
}

test_vault_connection() {
    echo "Testing connection to Vault..."
    ${VAULT_BIN} status >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: Unable to connect to Vault. Ensure Vault is running and accessible."
        exit 1
    fi
    echo "Vault connection successful."
}

get_or_set_vault_password() {
    local vault_path="secret/ipa/psql/ahv_admin"
    >&2 echo "Checking Vault for $vault_path..."
    local password=$(${VAULT_BIN} kv get -field=password "$vault_path" 2>/dev/null || true)

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

###############################################################################
# POSTGRES HELPER FUNCTIONS
###############################################################################
test_psql_connection() {
    local host="$1"
    local db="$2"
    local user="$3"
    local password="$4"

    echo "Testing PostgreSQL connection..."
    export PGPASSWORD="$password"
    psql -U "$user" -h "$host" -d "$db" -c '\\q' 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Unable to connect to PostgreSQL with provided credentials."
        exit 1
    fi
    echo "PostgreSQL connection successful."
}

check_or_create_database() {
    local host="$1"
    local db="$2"
    local user="$3"
    local password="$4"

    echo "Creating database '$db' if it does not exist..."
    export PGPASSWORD="$password"

    psql -U "$user" -h "$host" -d postgres -c "CREATE DATABASE \"$db\";" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Database '$db' might already exist or could not be created."
    else
        echo "Database '$db' created successfully."
    fi

    echo "Ensuring the 'leases' table exists in database '$db'..."
    local table_exists=$(psql -U "$user" -h "$host" -d "$db" -tAc \
      "SELECT 1 FROM information_schema.tables WHERE table_name='leases';")

    if [ "$table_exists" == "1" ]; then
        echo "'leases' table already exists in database '$db'."
        # TEXT with possible values: 'unknown', 'true', 'false'
        psql -U "$user" -h "$host" -d "$db" -c "
            ALTER TABLE leases
            ADD COLUMN IF NOT EXISTS preexisting_dns TEXT DEFAULT 'unknown';
        " >/dev/null 2>&1

        # If the existing column is BOOLEAN, convert it:
        # (If you definitely want to force it to TEXT.)
        local coltype=$(psql -U "$user" -h "$host" -d "$db" -tAc \
           "SELECT data_type FROM information_schema.columns
             WHERE table_name='leases' AND column_name='preexisting_dns';")

        if [ "$coltype" == "boolean" ]; then
            echo "Converting 'preexisting_dns' column from boolean to text..."
            psql -U "$user" -h "$host" -d "$db" -c "
                ALTER TABLE leases
                ALTER COLUMN preexisting_dns DROP DEFAULT;
                ALTER TABLE leases
                ALTER COLUMN preexisting_dns TYPE TEXT USING (CASE
                    WHEN preexisting_dns = true THEN 'true'
                    WHEN preexisting_dns = false THEN 'false'
                    ELSE 'unknown' END);
                ALTER TABLE leases
                ALTER COLUMN preexisting_dns SET DEFAULT 'unknown';
            " >/dev/null 2>&1
        fi

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
                preexisting_dns TEXT DEFAULT 'unknown',
                PRIMARY KEY (ip_address)
            );
        "
        echo "'leases' table created successfully."
    fi
}

display_database_indicator() {
    local host="$1"
    local db="$2"
    local user="$3"
    local password="$4"

    echo "Querying database '$db' to verify..."
    PGPASSWORD="$password" psql -U "$user" -h "$host" -d "$db" -c "SELECT current_database();" | grep "$db"
    echo "Database '$db' is ready and accessible."
}

###############################################################################
# save_credentials: store Prism Central credentials in Vault
###############################################################################
save_credentials() {
    local prism_central_ip="$1"
    local username="$2"
    local password="$3"

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

###############################################################################
# ipam_name_by_uuid / ipam_tag_by_uuid: associative arrays for IPAM VLAN data
###############################################################################
declare -A ipam_name_by_uuid
declare -A ipam_tag_by_uuid

###############################################################################
# get_ipam_vlans: populates ipam_name_by_uuid and ipam_tag_by_uuid
#   - skip "null" or missing pool_list
###############################################################################
get_ipam_vlans() {
    local offset=0
    local page_size=20
    local total_matches=1

    ipam_name_by_uuid=()  # reset arrays
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

        local this_length
        this_length=$(echo "$http_body" | jq '.metadata.length // 0')
        total_matches=$(echo "$http_body" | jq '.metadata.total_matches // 0')
        local this_offset
        this_offset=$(echo "$http_body" | jq '.metadata.offset // 0')
        log_debug 1 "metadata.offset=$this_offset, metadata.length=$this_length, total_matches=$total_matches"

        local entity_count
        entity_count=$(echo "$http_body" | jq '.entities | length')

        for (( i=0; i<entity_count; i++ )); do
            local has_pool=$(echo "$http_body" | jq -r ".entities[$i].spec.resources.ip_config.pool_list // empty")
            local vlan_id=$(echo "$http_body" | jq -r ".entities[$i].status.resources.vlan_id // empty")
            if [[ -n "$has_pool" && -n "$vlan_id" && "$vlan_id" != "null" ]]; then
                local suuid
                suuid=$(echo "$http_body" | jq -r ".entities[$i].metadata.uuid")
                local sname
                sname=$(echo "$http_body" | jq -r ".entities[$i].status.name")
                local stag
                stag=$(echo "$http_body" | jq -r ".entities[$i].status.resources.vlan_id")

                ipam_name_by_uuid["$suuid"]="$sname"
                ipam_tag_by_uuid["$suuid"]="$stag"

                log_debug 1 "Captured IPAM subnet: UUID=$suuid, Name=$sname, Tag=$stag"
            fi
        done

        offset=$((offset + this_length))
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

###############################################################################
# show_leases: just prints the table
###############################################################################
show_leases() {
    export PGPASSWORD="$(${VAULT_BIN} kv get -field=password secret/ipa/psql/ahv_admin)"
    psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "SELECT * FROM leases ORDER BY vm_name;"
}

###############################################################################
# cleanup_leases:
#   - Removes only entries with preexisting_dns='false' (dynamic)
#   - Where last_updated < now() - STALE_ENTRY_TIMEOUT
#   - Removes from DNS + DB
###############################################################################
cleanup_leases() {
    export PGPASSWORD="$(${VAULT_BIN} kv get -field=password secret/ipa/psql/ahv_admin)"

    local tsig_key
    tsig_key="$(${VAULT_BIN} kv get -field=tsig_key secret/ipa/dns)"
    local dns_server="$DNS_IP_ADDRESS"
    local domain="$DOMAIN_NAME"

    # Create TSIG key file
    local tsig_key_file="/tmp/ipa_ddns_key.key"
    cat > "$tsig_key_file" <<EOF
key "ipa_ddns_key" {
    algorithm hmac-sha256;
    secret "$tsig_key";
};
EOF
    trap 'rm -f "$tsig_key_file"' EXIT

    # We only want to delete from DNS if preexisting_dns='false'
    local stale_query="
        DELETE FROM leases
         WHERE preexisting_dns = 'false'
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

###############################################################################
# update_ddns:
#   - Looks at all rows in 'leases'
#   - If preexisting_dns='true', skip
#   - If DNS forward/reverse found and current preexisting_dns='unknown',
#       set preexisting_dns='true' (do NOT overwrite if it's 'false')
#   - Else proceed with ddns create + set preexisting_dns='false'
###############################################################################
update_ddns() {
    echo "Updating DDNS with entries from the database..."

    local tsig_key
    tsig_key="$(${VAULT_BIN} kv get -field=tsig_key secret/ipa/dns)"
    local dns_server="$DNS_IP_ADDRESS"
    local domain="$DOMAIN_NAME"
    local ttl="$STALE_ENTRY_TIMEOUT"

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

    export PGPASSWORD="$(${VAULT_BIN} kv get -field=password secret/ipa/psql/ahv_admin)"
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

        # If already 'true', skip entirely
        if [[ "$preexisting" == "true" ]]; then
            echo "Skipping $fqdn since preexisting_dns=true."
            continue
        fi

        # Check if DNS record already exists (forward or reverse)
        log_debug 1 "Checking forward DNS with: nslookup \"$fqdn\" \"$dns_server\""
        nslookup "$fqdn" "$dns_server" >/dev/null 2>&1
        local forward_rc=$?

        log_debug 1 "Checking reverse DNS with: nslookup \"$ip_address\" \"$dns_server\""
        nslookup "$ip_address" "$dns_server" >/dev/null 2>&1
        local reverse_rc=$?

        # If forward_rc=0 or reverse_rc=0 => Some DNS record is present
        if [[ $forward_rc -eq 0 || $reverse_rc -eq 0 ]]; then
            # Only mark 'true' if current preexisting_dns='unknown'
            if [[ "$preexisting" == "unknown" ]]; then
                echo "DNS record found for $fqdn or $ip_address. Marking preexisting_dns='true'."
                psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "
                    UPDATE leases
                       SET preexisting_dns = 'true'
                     WHERE ip_address = '$ip_address'
                       AND preexisting_dns = 'unknown';
                " >/dev/null 2>&1
            else
                echo "DNS record found, but existing preexisting_dns='$preexisting' so no change."
            fi
            continue
        fi

        # If no forward or reverse DNS record, then create it (mark 'false')
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
            echo "Successfully created/updated DDNS for $fqdn ($ip_address). Marking preexisting_dns='false'."
            psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "
                UPDATE leases
                   SET preexisting_dns = 'false'
                 WHERE ip_address = '$ip_address';
            " >/dev/null 2>&1
        else
            echo "Error: Failed to update DDNS for $fqdn ($ip_address)."
        fi

        rm -f "$nsupdate_file"
    done <<< "$result"

    echo "DDNS update process complete."
}

###############################################################################
# reset_db:
#   - Clear all rows from 'leases' table
#   - Does NOT remove DNS records
###############################################################################
reset_db() {
    export PGPASSWORD="$(${VAULT_BIN} kv get -field=password secret/ipa/psql/ahv_admin)"
    psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "
        DELETE FROM leases;
    " >/dev/null 2>&1

    if [ "$LOG_LEVEL" -eq 0 ]; then
        echo "reset_db completed."
    else
        echo "reset_db completed. All entries cleared from leases table."
    fi
}

###############################################################################
# prune_db:
#   - If first argument is "all", remove all entries with preexisting_dns='false'
#       from the database and DNS (nsupdate).
#   - If first argument is missing, show usage.
#   - Otherwise, treat each argument as either an IP or a hostname.
#       For each matching row in 'leases':
#         -> If preexisting_dns='false', remove from DNS + DB
#         -> If preexisting_dns='true', remove only from DB (DNS is not ours)
###############################################################################
prune_db() {
    # Check usage
    if [[ $# -lt 1 ]]; then
        echo "Usage:"
        echo "  prune_db all"
        echo "  prune_db <ip_or_hostname_1> [<ip_or_hostname_2> ...]"
        return 1
    fi

    local tsig_key
    tsig_key="$(${VAULT_BIN} kv get -field=tsig_key secret/ipa/dns)"
    local dns_server="$DNS_IP_ADDRESS"
    local domain="$DOMAIN_NAME"

    if [[ -z "$tsig_key" ]]; then
        echo "Error: TSIG key not found or could not be retrieved from Vault."
        return 1
    fi

    export PGPASSWORD="$(${VAULT_BIN} kv get -field=password secret/ipa/psql/ahv_admin)"

    # Create TSIG key file for nsupdate
    local tsig_key_file="/tmp/ipa_ddns_key.key"
    cat > "$tsig_key_file" <<EOF
key "ipa_ddns_key" {
    algorithm hmac-sha256;
    secret "$tsig_key";
};
EOF
    trap 'rm -f "$tsig_key_file"' EXIT

    # If we are pruning "all", remove any row with preexisting_dns='false'
    if [[ "$1" == "all" ]]; then
        echo "Pruning ALL dynamic (preexisting_dns='false') entries from database & DNS..."

        local all_query="SELECT ip_address, hostname FROM leases WHERE preexisting_dns='false';"
        local all_result
        all_result="$(psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -t -A -F '|' -c "$all_query")"

        if [[ -z "$all_result" ]]; then
            echo "No dynamic entries found to prune."
            return 0
        fi

        # Remove each dynamic entry from DNS, then from DB
        while IFS='|' read -r ip_address hostname; do
            [[ -z "$hostname" ]] && continue
            local fqdn="$hostname.$domain"

            echo "Removing dynamic DNS record for $fqdn ($ip_address)..."
            # Build nsupdate file to delete the record
            local nsupdate_file="/tmp/nsupdate_prune_${hostname}.txt"
            cat > "$nsupdate_file" <<EOF
server $dns_server
zone $domain
update delete $fqdn A
send
EOF
            nsupdate -k "$tsig_key_file" "$nsupdate_file"
            if [ $? -eq 0 ]; then
                echo "DNS entry $fqdn removed."
            else
                echo "Warning: Failed to remove DNS entry for $fqdn."
            fi
            rm -f "$nsupdate_file"
        done <<< "$all_result"

        # Finally remove them from the DB
        psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "
            DELETE FROM leases
             WHERE preexisting_dns='false';
        " >/dev/null 2>&1

        echo "All dynamic entries removed from the database."
        return 0
    fi

    # Otherwise, each argument is an IP or hostname to remove
    echo "Pruning specified entries..."
    # Notice we do NOT shift here if $1 != 'all'
    for arg in "$@"; do
        # Find a row by IP or hostname
        local row_query="
            SELECT ip_address, hostname, preexisting_dns
              FROM leases
             WHERE ip_address = '$arg'
                OR hostname   = '$arg'
             LIMIT 1;
        "
        local row
        row="$(psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -t -A -F '|' -c "$row_query")"

        if [[ -z "$row" ]]; then
            echo "No matching lease database entry found for '$arg'. Skipping..."
            continue
        fi

        local ip_address
        ip_address="$(echo "$row" | cut -d'|' -f1)"
        local hostname
        hostname="$(echo "$row" | cut -d'|' -f2)"
        local preexisting_dns_val
        preexisting_dns_val="$(echo "$row" | cut -d'|' -f3)"

        echo "Found matching entry: $ip_address / $hostname (preexisting_dns=$preexisting_dns_val). Removing..."

        # If the entry was dynamically created, remove from DNS
        if [[ "$preexisting_dns_val" == "false" ]]; then
            local fqdn="$hostname.$domain"
            local nsupdate_file="/tmp/nsupdate_prune_${hostname}.txt"
            cat > "$nsupdate_file" <<EOF
server $dns_server
zone $domain
update delete $fqdn A
send
EOF
            nsupdate -k "$tsig_key_file" "$nsupdate_file"
            if [ $? -eq 0 ]; then
                echo "DNS entry $fqdn removed."
            else
                echo "Warning: Failed to remove DNS entry for $fqdn."
            fi
            rm -f "$nsupdate_file"
        fi

        # Now remove from the database
        local delete_query="
            DELETE FROM leases
             WHERE ip_address = '$ip_address';
        "
        psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "$delete_query" >/dev/null 2>&1
        echo "Database entry for $ip_address removed."
    done
}

###############################################################################
# get_leases:
#   1) gather data from Nutanix Prism Central
#   2) only insert IP addresses for VLANs recognized in IPAM
#   3) insert with preexisting_dns='unknown' if it's a new row
#      do NOT overwrite preexisting_dns if the row already exists
###############################################################################
get_leases() {
    echo "Starting get_leases..."

    # Fetch prism_central_ip + encoded_credentials from Vault
    prism_central_ip=$(${VAULT_BIN} kv get -field=value "secret/nutanix/prism_central_ip" 2>/dev/null)
    if [ -z "$prism_central_ip" ]; then
        echo "Error: Prism Central IP not found in Vault. Run 'save_credentials' first."
        return 1
    fi

    encoded_credentials=$(${VAULT_BIN} kv get -field=value "secret/nutanix/encoded_credentials" 2>/dev/null)
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

    # Load CSV host substitution map
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

    # Export PGPASSWORD once up front (since we do many inserts)
    export PGPASSWORD="$(${VAULT_BIN} kv get -field=password secret/ipa/psql/ahv_admin)"

    while [ "$offset" -lt "$total_vm_matches" ]; do
        local vm_payload='{"kind":"vm","offset":'"$offset"',"length":'"$page_size"'}'
        log_debug 1 "Calling vms/list with offset=$offset, length=$page_size"

        local response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
            "https://$prism_central_ip:9440/api/nutanix/v3/vms/list" \
            -H "Authorization: Basic $encoded_credentials" \
            -H "Content-Type: application/json" \
            -d "$vm_payload" \
            -k)

        local http_body
        http_body=$(echo "$response" | sed -e 's/HTTP_STATUS:.*//g')
        local http_status
        http_status=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')

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

        # Parse out each VM entity
        echo "$http_body" | jq -c '.entities[]' | while read -r entity; do
            local vm_name
            vm_name=$(echo "$entity" | jq -r '.status.name // empty')
            log_debug 1 "Processing VM entity with name: $vm_name"

            # For each NIC
            local nic_list
            nic_list=$(echo "$entity" | jq -c '.status.resources.nic_list[]?')

            while IFS= read -r nic; do
                # Guard for empty or "null" subnet_reference.uuid
                local vlan_uuid
                vlan_uuid=$(echo "$nic" | jq -r '.subnet_reference.uuid // empty')
                if [[ -z "$vlan_uuid" || "$vlan_uuid" == "null" ]]; then
                    log_debug 1 "No VLAN UUID on NIC for $vm_name—skipping."
                    continue
                fi

                # If we do not have an IPAM entry for this VLAN UUID, skip
                if [[ -z "${ipam_name_by_uuid[$vlan_uuid]+exists}" ]]; then
                    log_debug 1 "Skipping NIC on $vm_name: VLAN UUID $vlan_uuid not IPAM-managed."
                    continue
                fi

                local vlan_name="${ipam_name_by_uuid[$vlan_uuid]}"
                local vlan_tag="${ipam_tag_by_uuid[$vlan_uuid]}"

                # For each IP endpoint
                local ip_endpoint_list
                ip_endpoint_list=$(echo "$nic" | jq -c '.ip_endpoint_list[]?')

                while IFS= read -r ip_ep; do
                    local ip_type
                    ip_type=$(echo "$ip_ep" | jq -r '.ip_type')
                    local ip_address
                    ip_address=$(echo "$ip_ep" | jq -r '.ip // empty')
                    local mac_address
                    mac_address=$(echo "$nic" | jq -r '.mac_address // empty')

                    # If ip_address is empty, skip
                    if [[ -z "$ip_address" ]]; then
                        continue
                    fi

                    # Only proceed if ip_type is in {DHCP,LEARNED,ASSIGNED,STATIC,null}
                    if [[ "$ip_type" != "DHCP" && "$ip_type" != "LEARNED" \
                          && "$ip_type" != "ASSIGNED" && "$ip_type" != "STATIC" \
                          && "$ip_type" != "null" ]]; then
                        log_debug 2 "Skipping IP $ip_address (type=$ip_type) on VM $vm_name"
                        continue
                    fi

                    log_debug 1 "VM $vm_name has IP $ip_address ($ip_type), VLAN UUID $vlan_uuid => $vlan_name"

                    # Normalize and possibly substitute
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

                    # Insert or update in the DB
                    #   1) If new row => preexisting_dns='unknown'
                    #   2) If existing row => do NOT overwrite preexisting_dns
                    psql -U ahv_admin -h "$POSTGRES_HOST" -d "$AHV_IPAM_DB" -c "
                        INSERT INTO leases (
                            ip_address, vm_name, hostname, mac_address,
                            vlan_uuid, vlan_name, vlan_tag, last_updated
                        )
                        VALUES (
                            '$ip_address', '$vm_name', '$final_hostname', '$mac_address',
                            '$vlan_uuid', '$vlan_name', $vlan_tag, NOW()
                        )
                        ON CONFLICT (ip_address) DO UPDATE
                            SET vm_name      = EXCLUDED.vm_name,
                                hostname     = EXCLUDED.hostname,
                                mac_address  = EXCLUDED.mac_address,
                                vlan_uuid    = EXCLUDED.vlan_uuid,
                                vlan_name    = EXCLUDED.vlan_name,
                                vlan_tag     = EXCLUDED.vlan_tag,
                                last_updated = NOW()
                            -- We do NOT overwrite preexisting_dns here
                            -- so existing 'true' or 'false' remains untouched
                            ;
                    " >/dev/null 2>&1

                    (( lease_changes++ ))
                done < <(printf "%s\n" "$ip_endpoint_list")
            done < <(printf "%s\n" "$nic_list")
        done

        offset=$(( offset + this_length ))
        if [ "$this_length" -eq 0 ]; then
            log_debug 1 "No more VMs returned; ending pagination."
            break
        fi
    done

    echo "get_leases completed. $lease_changes hosts populated in lease table."
}

###############################################################################
# show_hostnames:
#   - Lists all from 'leases' => prints normalized name plus the current hostname
###############################################################################
show_hostnames() {
    echo "Fetching VM names from the leases database..."
    export PGPASSWORD="$(${VAULT_BIN} kv get -field=password secret/ipa/psql/ahv_admin)"

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

###############################################################################
# setup_cron:
#   - create a cron job for get_leases, update_ddns, cleanup_leases
###############################################################################
setup_cron() {
    local cron_job="*/$NUTANIX_POLLING_INTERVAL * * * * $(realpath "$0") get_leases >> /var/log/ahv_ipam.log 2>&1; \
$(realpath "$0") update_ddns >> /var/log/ahv_ipam.log 2>&1; \
$(realpath "$0") cleanup_leases >> /var/log/ahv_ipam.log 2>&1"

    echo "Adding the following cron job:"
    echo "$cron_job"

    (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
    echo "Cron job added successfully."
}

###############################################################################
# Main: load_config, parse command line
###############################################################################
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
    show_hostnames)
        show_hostnames
        ;;
    reset_db)
        reset_db
        ;;
    prune_db)
        prune_db  "${@:2}"
        ;;
    *)
        usage
        ;;
esac

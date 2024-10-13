#!/bin/bash

set -e

# Initialize DEBUG to false
DEBUG=false

# Function to display usage information
usage() {
    echo "Usage: $0 [--ns <namespace> 'vpn_ns'] [--uid <uid> '1337'] [--net <network/CIDR>] --vpn-cmd \"<vpn_command>\" [--cmd \"<additional_command>\"] [--cleanup] [--debug]"
    echo "Examples"
    echo "\t sudo bash $0 --cmd 'curl -s ifconfig.me' --uid 1338 --ns new_ns --net 10.100.100.0/24"
    echo "\t sudo bash $0 --cleanup --ns new_ns --uid 1338"
    exit 1
}

# Logging functions
log_debug() {
    if [ "$DEBUG" = true ]; then
        echo "[DEBUG] $@"
    fi
}

log_info() {
    if [ "$DEBUG" = true ]; then
        echo "[INFO] $@"
    fi
}

log_error() {
    echo "[ERROR] $@" >&2
}

# Function to add or delete a routing table
rt_table() {
    ACTION="$1"
    NAME="$2"
    if grep -qi 'ID=arch' /etc/os-release 2>/dev/null; then
        RT_TABLES="/usr/share/iproute2/rt_tables"
    else
        RT_TABLES="/etc/iproute2/rt_tables"
    fi
    case "$ACTION" in
        add)
            grep -qw "$NAME" "$RT_TABLES" || {
                ID=$(comm -23 <(seq 100 252 | sort) <(awk '{print $1}' "$RT_TABLES" | sort) | head -n1)
                echo "$ID $NAME" | sudo tee -a "$RT_TABLES" >/dev/null
                log_info "Routing table '$NAME' added with ID '$ID'."
            }
            ;;
        del)
            sudo sed -i "/\b$NAME\b/d" "$RT_TABLES"
            log_info "Routing table '$NAME' deleted."
            ;;
    esac
}

# Function to add a system user
add_user() {
    USERNAME="$1"
    USERUID="$2"

    if id "$USERNAME" >/dev/null 2>&1; then
        log_info "User '$USERNAME' already exists."
    else
        if getent passwd "$USERUID" >/dev/null 2>&1; then
            log_error "UID '$USERUID' is not available."
            exit 1
        fi
        useradd -r -u "$USERUID" -M -s /usr/sbin/nologin "$USERNAME"
        mkdir -p /tmp/"$USERNAME"
        chown "$USERNAME":"$USERNAME" /tmp/"$USERNAME"
        log_info "User '$USERNAME' added with UID '$USERUID'."
    fi
}

# Function to run VPN command inside the namespace
run_vpn_command() {
    NS_NAME="$1"
    VPN_COMMAND="$2"
    USERNAME="$1"

    log_info "Starting VPN command in namespace '$NS_NAME'."
    ip netns exec "$NS_NAME" sudo -u "$USERNAME" nohup bash -c "cd /tmp/$USERNAME && $VPN_COMMAND" >/var/log/${NS_NAME}_vpn.log 2>&1 &
}

# Function to execute an additional command inside the namespace
execute_command() {
    NS_NAME="$1"
    CMD="$2"

    if [ -n "$CMD" ]; then
        log_info "Executing additional command in namespace '$NS_NAME'."
        ip netns exec "$NS_NAME" bash -c "$CMD" | tee /var/log/${NS_NAME}_additional_cmd.log
    fi
}

# Function to wait for the VPN interface to appear
wait_for_interface() {
    NS_NAME="$1"
    IF_NAME="$2"
    TIMEOUT=30
    INTERVAL=1
    elapsed=0

    log_debug "Waiting for interface '$IF_NAME' in namespace '$NS_NAME'."

    while ! ip netns exec "$NS_NAME" ip link show "$IF_NAME" >/dev/null 2>&1; do
        sleep "$INTERVAL"
        elapsed=$((elapsed + INTERVAL))
        if [ "$elapsed" -ge "$TIMEOUT" ]; then
            log_error "Interface '$IF_NAME' did not appear in namespace '$NS_NAME' after $TIMEOUT seconds."
            exit 1
        fi
    done

    log_info "Interface '$IF_NAME' detected in namespace '$NS_NAME'."
}

# Function to convert IP address to integer
ip_to_int() {
    local IFS=.
    read -r i1 i2 i3 i4 <<< "$1"
    echo "$(( (i1 << 24) + (i2 << 16) + (i3 << 8) + i4 ))"
}

# Function to convert integer to IP address
int_to_ip() {
    local ip=$1
    echo "$(( (ip >> 24) & 0xFF )).$(( (ip >> 16) & 0xFF )).$(( (ip >> 8 ) & 0xFF )).$(( ip & 0xFF ))"
}

# Function to set up the network namespace and VPN
setup_namespace() {
    NS_NAME="$1"
    VPN_COMMAND="$2"
    VPN_APP_UID="$3"
    VPN_IF_NAME="$4"
    CMD="$5"
    NET_CIDR="$6"

    EXEC_NS="ip netns exec $NS_NAME"
    LOCAL_IF_GW=$(ip route | head -n 1 | awk '{print $5}')

    # Parse network CIDR
    NETWORK=$(echo "$NET_CIDR" | cut -d'/' -f1)
    PREFIX=$(echo "$NET_CIDR" | cut -d'/' -f2)

    # Convert network IP to integer
    NETWORK_INT=$(ip_to_int "$NETWORK")

    # Calculate Host IP (network +1)
    HOST_IP_INT=$((NETWORK_INT + 1))
    HOST_IP=$(int_to_ip "$HOST_IP_INT")

    # Calculate Namespace IP (network +2)
    NS_IP_INT=$((NETWORK_INT + 2))
    NS_IP=$(int_to_ip "$NS_IP_INT")

    # Calculate Namespace IP (network +2)
    NS_VPN_INT=$((NETWORK_INT + 3))
    NS_VPN_IP=$(int_to_ip "$NS_VPN_INT")

    log_info "Network: $NETWORK/$PREFIX"
    log_info "Host IP: $HOST_IP"
    log_info "Namespace IP: $NS_IP"

    log_info "Setting up routing table '$NS_NAME'."
    rt_table add "$NS_NAME"

    log_info "Adding user '$NS_NAME' with UID '$VPN_APP_UID'."
    add_user "$NS_NAME" "$VPN_APP_UID"

    log_info "Creating network namespace '$NS_NAME'."
    ip netns add "$NS_NAME"
    sleep 1

    log_info "Enabling IP forwarding."
    sysctl -w net.ipv4.ip_forward=1

    # Define unique veth pair names based on namespace, max 15 chars
    HOST_SUFFIX="_h"
    NS_SUFFIX="_n"
    MAX_NS_LEN=$((15 - 2)) # 13
    TRUNC_NS=$(echo "$NS_NAME" | cut -c1-"$MAX_NS_LEN")
    VETH_HOST="${TRUNC_NS}${HOST_SUFFIX}"
    VETH_NS="${TRUNC_NS}${NS_SUFFIX}"

    log_info "Creating veth pair '$VETH_HOST' <-> '$VETH_NS'."
    ip link add "$VETH_HOST" type veth peer name "$VETH_NS"

    log_info "Configuring iptables MASQUERADE for network '$NET_CIDR'."
    iptables -t nat -C POSTROUTING -o "$LOCAL_IF_GW" -s "$NET_CIDR" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -I POSTROUTING -o "$LOCAL_IF_GW" -s "$NET_CIDR" -j MASQUERADE

    log_info "Moving '$VETH_NS' to namespace '$NS_NAME'."
    ip link set "$VETH_NS" netns "$NS_NAME"

    log_info "Setting up loopback interface in namespace."
    $EXEC_NS ip link set dev lo up
    sleep 1

    log_info "Assigning IP addresses."
    ip address add "$HOST_IP"/"$PREFIX" dev "$VETH_HOST"
    $EXEC_NS ip address add "$NS_IP"/"$PREFIX" dev "$VETH_NS"

    log_info "Bringing up interfaces."
    ip link set dev "$VETH_HOST" up
    $EXEC_NS ip link set dev "$VETH_NS" up
    sleep 1

    log_info "Configuring DNS for namespace."
    mkdir -p /etc/netns/"$NS_NAME"
    echo "nameserver 8.8.8.8" | sudo tee /etc/netns/"$NS_NAME"/resolv.conf >/dev/null

    log_info "Adding default route via '$HOST_IP'."
    $EXEC_NS ip route add default via "$HOST_IP"

    log_info "Starting VPN program."
    run_vpn_command "$NS_NAME" "$VPN_COMMAND"

    log_info "Waiting for VPN interface '$VPN_IF_NAME'."
    wait_for_interface "$NS_NAME" "$VPN_IF_NAME"

    log_info "Configuring routes and rules in table '$NS_NAME'."
    $EXEC_NS ip route add default via "$HOST_IP" dev "$VETH_NS" table "$NS_NAME"
    $EXEC_NS ip rule add from all uidrange "$VPN_APP_UID"-"$VPN_APP_UID" table "$NS_NAME"
    $EXEC_NS ip route del default via "$HOST_IP"
    $EXEC_NS ip route add default dev "$VPN_IF_NAME"

    # Execute additional command if provided
    execute_command "$NS_NAME" "$CMD"

}

# Function to clean up the network namespace and VPN
cleanup() {
    NS_NAME="$1"
    VPN_COMMAND="$2"
    NET_CIDR="$3"

    log_info "Cleaning up namespace '$NS_NAME'."
    pkill -f "$VPN_COMMAND" || log_info "VPN program not running."
    ip netns del "$NS_NAME" || log_info "Namespace '$NS_NAME' does not exist."

    # Parse network CIDR
    NETWORK=$(echo "$NET_CIDR" | cut -d'/' -f1)
    PREFIX=$(echo "$NET_CIDR" | cut -d'/' -f2)

    # Convert network IP to integer
    NETWORK_INT=$(ip_to_int "$NETWORK")

    # Calculate Host IP (network +1)
    HOST_IP_INT=$((NETWORK_INT + 1))
    HOST_IP=$(int_to_ip "$HOST_IP_INT")

    iptables -t nat -D POSTROUTING -o "$LOCAL_IF_GW" -s "$NET_CIDR" -j MASQUERADE 2>/dev/null || log_info "iptables rule not found."

    # Define unique veth pair names based on namespace
    HOST_SUFFIX="_h"
    MAX_NS_LEN=$((15 - 2)) # 13
    TRUNC_NS=$(echo "$NS_NAME" | cut -c1-"$MAX_NS_LEN")
    VETH_HOST="${TRUNC_NS}${HOST_SUFFIX}"

    ip link del "$VETH_HOST" 2>/dev/null || log_info "Interface '$VETH_HOST' does not exist."

    rm -rf /etc/netns/"$NS_NAME"
    userdel "$NS_NAME" 2>/dev/null || log_info "User '$NS_NAME' does not exist."
    setcap cap_net_admin=+ep /usr/bin/sslocal 2>/dev/null || log_info "Failed to set capabilities for sslocal."
    log_info "Cleanup completed."
}

# Function to execute additional commands when namespace exists
execute_existing_namespace_commands() {
    NS_NAME="$1"
    VPN_COMMAND="$2"
    CMD="$3"

    # Execute VPN command if provided
    if [ -n "$VPN_COMMAND" ]; then
        log_info "Attempting to start VPN command."
        # Check if VPN is already running
        if pgrep -f "$VPN_COMMAND" >/dev/null 2>&1; then
            log_info "VPN command is already running."
        else
            run_vpn_command "$NS_NAME" "$VPN_COMMAND"
        fi
    fi

    # Execute additional command if provided
    if [ -n "$CMD" ]; then
        execute_command "$NS_NAME" "$CMD"
    fi

}

# Function to convert IP address to integer
ip_to_int() {
    local IFS=.
    read -r i1 i2 i3 i4 <<< "$1"
    echo "$(( (i1 << 24) + (i2 << 16) + (i3 << 8) + i4 ))"
}

# Function to convert integer to IP address
int_to_ip() {
    local ip=$1
    echo "$(( (ip >> 24) & 0xFF )).$(( (ip >> 16) & 0xFF )).$(( (ip >> 8 ) & 0xFF )).$(( ip & 0xFF ))"
}

# Main Script Execution

# Parsing arguments
NS_NAME="vpn_ns"
VPN_APP_UID=1337
VPN_COMMAND="sslocal --online-config-url https://..."
CMD=""
CLEANUP=false
NET_CIDR="10.99.99.0/24"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --ns)
            NS_NAME="$2"
            shift 2
            ;;
        --uid)
            VPN_APP_UID="$2"
            shift 2
            ;;
        --net)
            NET_CIDR="$2"
            shift 2
            ;;
        --vpn-cmd)
            VPN_COMMAND="$2"
            shift 2
            ;;
        --cmd)
            CMD="$2"
            shift 2
            ;;
        --cleanup)
            CLEANUP=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        *)
            usage
            ;;
    esac
done

if [ "$CLEANUP" = false ] && [ -z "$VPN_COMMAND" ] && [ -z "$CMD" ]; then
    log_error "Error: VPN command is required unless using --cleanup."
    usage
fi

LOCAL_IF_GW=$(ip route | head -n 1 | awk '{print $5}')

if [ "$CLEANUP" = true ]; then
    cleanup "$NS_NAME" "$VPN_COMMAND" "$NET_CIDR"
    exit 0
fi

# Check if namespace exists
if ip netns list | grep -qw "$NS_NAME"; then
    log_info "Namespace '$NS_NAME' already exists."
    # Check if user exists
    if id "$NS_NAME" >/dev/null 2>&1; then
        log_info "User '$NS_NAME' already exists."
        execute_existing_namespace_commands "$NS_NAME" "$VPN_COMMAND" "$CMD"
    else
        log_error "Error: Namespace '$NS_NAME' exists but user '$NS_NAME' does not. Please clean up and try again."
        exit 1
    fi
else
    # Namespace does not exist, proceed with setup
    if [ -z "$VPN_COMMAND" ] && [ -z "$CMD" ]; then
        log_error "Error: VPN command is required to set up the namespace."
        usage
    fi
    setup_namespace "$NS_NAME" "$VPN_COMMAND" "$VPN_APP_UID" "vpn" "$CMD" "$NET_CIDR"
fi                                                                       

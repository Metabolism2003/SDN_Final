#!/bin/bash

# ============================================================
# SDN/NFV Final Project - Topology Utility Script
# ============================================================

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# ============================================================
# TEAM CONFIGURATION - EDIT THESE 3 LINES ONLY
# ============================================================
PEERID=35
MYID=34
PEER2ID=36
# ============================================================

# --- Constants & Names ---
HOST_IMAGE=sdnfinal-host
FRR_IMAGE=sdnfinal-frrouting
H1_CONTAINER=h1
H2_CONTAINER=h2      
H3_CONTAINER=h3       
FRR_CONTAINER=frr
ONOS_CONTAINER=onos
R1_CONTAINER=r1

OVS1=ovs1
OVS2=ovs2

# Interface Names
VETH_VXLANTA=vethvxlanta
VETH_OVS1OVS2=vethovs1ovs2
VETH_OVS2H1=vethovs2h1
VETH_OVS2H2=vethovs2h2      
VETH_OVS1FRR=vethovs1frr
VETH_R1H3=vethr1h3          
VETH_OVS1R1=vethovs1r1
VETH_ANY1=vethany1          
VETH_ANY2=vethany2          

# ============================================================
# Helper Functions
# ============================================================

# Creates a veth pair and disables IPv6 autoconf
function create_veth_pair {
    ip link add $1 type veth peer name $2
    ip link set $1 up
    ip link set $2 up
    sysctl -w net.ipv6.conf.$1.autoconf=0 > /dev/null
    sysctl -w net.ipv6.conf.$2.autoconf=0 > /dev/null
    ip -6 addr flush dev $1
    ip -6 addr flush dev $2
}

# Add a container
function add_container {
    docker run -dit --network=none --privileged --cap-add NET_ADMIN --cap-add SYS_MODULE \
        --hostname $2 --name $2 ${@:3} $1
    
    # Expose container network namespace to host
    pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$2"))
    mkdir -p /var/run/netns
    # Force remove existing symlink if it exists to avoid errors on restart
    rm -f /var/run/netns/$pid
    ln -s /proc/$pid/ns/net /var/run/netns/$pid
}

# Remove ipv6 autoconf inside container
function remove_v6_autoconf {
    pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$1"))
    ip netns exec "$pid" sysctl -w net.ipv6.conf.$2.autoconf=0 > /dev/null
    ip netns exec "$pid" ip -6 addr flush dev $2
}

# Remove a container
function remove_container {
    if docker ps -a --format '{{.Names}}' | grep -q "^$1$"; then
        echo "Removing container $1..."
        pid=$(docker inspect -f '{{.State.Pid}}' $1)
        [ -n "$pid" ] && rm -f "/var/run/netns/$pid"
        docker stop $1 > /dev/null
        docker rm $1 > /dev/null
    fi
}

# Set container interface IP and Gateway
function set_intf_container {
    pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$1"))
    ifname=$2
    ipaddr=$3
    gateway=$4

    echo "Configuring $ifname on $1 ($ipaddr)..."
    
    # Move interface to container namespace if not already there
    if ip link show "$ifname" > /dev/null 2>&1; then
        ip link set "$ifname" netns "$pid"
    fi

    # Configure IP
    [ -n "$ipaddr" ] && ip netns exec "$pid" ip addr add "$ipaddr" dev "$ifname"
    ip netns exec "$pid" ip link set "$ifname" up
    
    # Configure Gateway
    [ -n "$gateway" ] && ip netns exec "$pid" route add default gw "$gateway"
}

# Set container interface IPv6 and Gateway
function set_v6intf_container {
    pid=$(docker inspect -f '{{.State.Pid}}' $(docker ps -aqf "name=$1"))
    ifname=$2
    ipaddr=$3
    gateway=$4

    # Move interface if needed
    if ip link show "$ifname" > /dev/null 2>&1; then
        ip link set "$ifname" netns "$pid"
    fi

    [ -n "$ipaddr" ] && ip netns exec "$pid" ip addr add "$ipaddr" dev "$ifname"
    ip netns exec "$pid" ip link set "$ifname" up
    [ -n "$gateway" ] && ip netns exec "$pid" route -6 add default gw "$gateway"
}

# Connect Bridge -> Container
function build_bridge_container_path {
    create_veth_pair $1 $2
    brctl addif $3 $1
    set_intf_container $4 $2 $5 $6
}

# Connect OVS -> OVS
function build_ovs_path {
    create_veth_pair $1 $2
    ovs-vsctl add-port $3 $1
    ovs-vsctl add-port $4 $2
}

# Connect OVS -> Container
function build_ovs_container_path {
    create_veth_pair $1 $2
    ovs-vsctl add-port $3 $1
    set_intf_container $4 $2 $5 $6
}

# ============================================================
# DEPLOY FUNCTION
# ============================================================
function deploy {
    echo "========================================="
    echo "Deploying SDN/NFV Final Project 2025"
    echo "ID: $MYID | Peer1: $PEERID | Peer2: $PEER2ID"
    echo "========================================="

    # Build images if missing
    if [[ "$(docker images -q $HOST_IMAGE 2> /dev/null)" == "" ]]; then
        echo "Building host image..."
        docker build containers/host -t $HOST_IMAGE
    fi
    if [[ "$(docker images -q $FRR_IMAGE 2> /dev/null)" == "" ]]; then
        echo "Building FRR image..."
        docker build containers/frr -t $FRR_IMAGE
    fi

    # Link for ONOS connection
    create_veth_pair ${VETH_VXLANTA}0 ${VETH_VXLANTA}1
    ip a add 192.168.100.1/24 dev ${VETH_VXLANTA}1

    # Start ONOS
    echo "Starting ONOS..."
    docker run -dit --privileged --hostname $ONOS_CONTAINER --name $ONOS_CONTAINER \
        -e ONOS_APPS=drivers,openflow,fpm,gui2 \
        -p 2620:2620 -p 6653:6653 -p 8101:8101 -p 8181:8181 \
        --tty --interactive onosproject/onos:2.7.0

    # Start Containers
    echo "Starting network containers..."
    add_container $HOST_IMAGE $H1_CONTAINER
    add_container $HOST_IMAGE $H2_CONTAINER    
    add_container $HOST_IMAGE $H3_CONTAINER    
    add_container $FRR_IMAGE $FRR_CONTAINER \
        -v $(pwd)/config/daemons:/etc/frr/daemons \
        -v $(pwd)/config/frr/frr.conf:/etc/frr/frr.conf
    add_container $FRR_IMAGE $R1_CONTAINER \
        -v $(pwd)/config/daemons:/etc/frr/daemons \
        -v $(pwd)/config/r1/frr.conf:/etc/frr/frr.conf

    # Create OVS switches
    echo "Configuring OVS switches..."
    ovs-vsctl add-br $OVS1 -- set bridge $OVS1 protocols=OpenFlow14 -- set-controller $OVS1 tcp:192.168.100.1:6653
    ovs-vsctl add-br $OVS2 -- set bridge $OVS2 protocols=OpenFlow14 -- set-controller $OVS2 tcp:192.168.100.1:6653

    # Link OVS1 <-> OVS2
    build_ovs_path ${VETH_OVS1OVS2}0 ${VETH_OVS1OVS2}1 $OVS1 $OVS2

    # Connect OVS2 to ONOS via VXLAN interface
    ovs-vsctl add-port $OVS2 ${VETH_VXLANTA}0

    # Host 1 -> OVS2
    build_ovs_container_path ${VETH_OVS2H1}0 ${VETH_OVS2H1}1 $OVS2 $H1_CONTAINER 172.16.$MYID.2/24 172.16.$MYID.1
    remove_v6_autoconf $H1_CONTAINER ${VETH_OVS2H1}1
    set_v6intf_container $H1_CONTAINER ${VETH_OVS2H1}1 2a0b:4e07:c4:$MYID::2/64 2a0b:4e07:c4:$MYID::1

    # Host 2 -> OVS2
    build_ovs_container_path ${VETH_OVS2H2}0 ${VETH_OVS2H2}1 $OVS2 $H2_CONTAINER 172.16.$MYID.3/24 172.16.$MYID.1
    remove_v6_autoconf $H2_CONTAINER ${VETH_OVS2H2}1
    set_v6intf_container $H2_CONTAINER ${VETH_OVS2H2}1 2a0b:4e07:c4:$MYID::3/64 2a0b:4e07:c4:$MYID::1

    # FRR -> OVS1 (The BGP Router)
    echo "Configuring FRR interfaces..."
    build_ovs_container_path ${VETH_OVS1FRR}0 ${VETH_OVS1FRR}1 $OVS1 $FRR_CONTAINER 172.16.$MYID.69/24
    remove_v6_autoconf $FRR_CONTAINER ${VETH_OVS1FRR}1
    set_v6intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 192.168.100.3/24
    set_v6intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 192.168.63.1/24
    set_v6intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 192.168.70.$MYID/24
    set_v6intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 fd63::1/64
    set_v6intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 fd70::$MYID/64
    set_v6intf_container $FRR_CONTAINER ${VETH_OVS1FRR}1 2a0b:4e07:c4:$MYID::69/64

    # R1 (Internal Router) -> Host 3
    create_veth_pair ${VETH_R1H3}0 ${VETH_R1H3}1
    set_intf_container $R1_CONTAINER ${VETH_R1H3}0 172.17.$MYID.1/24
    remove_v6_autoconf $R1_CONTAINER ${VETH_R1H3}0
    set_v6intf_container $R1_CONTAINER ${VETH_R1H3}0 2a0b:4e07:c4:1$MYID::1/64
    
    set_intf_container $H3_CONTAINER ${VETH_R1H3}1 172.17.$MYID.2/24 172.17.$MYID.1
    remove_v6_autoconf $H3_CONTAINER ${VETH_R1H3}1
    set_v6intf_container $H3_CONTAINER ${VETH_R1H3}1 2a0b:4e07:c4:1$MYID::2/64 2a0b:4e07:c4:1$MYID::1

    # R1 -> OVS1
    build_ovs_container_path ${VETH_OVS1R1}0 ${VETH_OVS1R1}1 $OVS1 $R1_CONTAINER 192.168.63.2/24
    remove_v6_autoconf $R1_CONTAINER ${VETH_OVS1R1}1
    set_v6intf_container $R1_CONTAINER ${VETH_OVS1R1}1 fd63::2/64

    # VXLAN Tunnels
    echo "Creating VXLAN Tunnels..."
    ovs-vsctl add-port $OVS2 vxta -- set interface vxta type=vxlan options:remote_ip=192.168.60.$MYID
    ovs-vsctl add-port $OVS2 vxpeer1 -- set interface vxpeer1 type=vxlan options:remote_ip=192.168.61.$PEERID
    ovs-vsctl add-port $OVS2 vxpeer2 -- set interface vxpeer2 type=vxlan options:remote_ip=192.168.61.$PEER2ID

    # Anycast Services
    echo "Setting up Anycast servers..."
    docker run -d --name anycast1 --network=none --privileged --cap-add NET_ADMIN traefik/whoami
    pid=$(docker inspect -f '{{.State.Pid}}' anycast1)
    rm -f /var/run/netns/$pid
    ln -s /proc/$pid/ns/net /var/run/netns/$pid
    
    create_veth_pair ${VETH_ANY1}0 ${VETH_ANY1}1
    ovs-vsctl add-port $OVS1 ${VETH_ANY1}0
    set_intf_container anycast1 ${VETH_ANY1}1 172.16.$MYID.100/24 172.16.$MYID.1
    remove_v6_autoconf anycast1 ${VETH_ANY1}1
    set_v6intf_container anycast1 ${VETH_ANY1}1 2a0b:4e07:c4:$MYID::100/64 2a0b:4e07:c4:$MYID::1
    
    docker run -d --name anycast2 --network=none --privileged --cap-add NET_ADMIN traefik/whoami
    pid=$(docker inspect -f '{{.State.Pid}}' anycast2)
    rm -f /var/run/netns/$pid
    ln -s /proc/$pid/ns/net /var/run/netns/$pid
    
    create_veth_pair ${VETH_ANY2}0 ${VETH_ANY2}1
    ovs-vsctl add-port $OVS2 ${VETH_ANY2}0
    set_intf_container anycast2 ${VETH_ANY2}1 172.16.$MYID.100/24 172.16.$MYID.1
    remove_v6_autoconf anycast2 ${VETH_ANY2}1
    set_v6intf_container anycast2 ${VETH_ANY2}1 2a0b:4e07:c4:$MYID::100/64 2a0b:4e07:c4:$MYID::1

    echo "========================================="
    echo "Deployment Complete."
    echo "========================================="
}

# ============================================================
# GENERATE CONFIGURATION (2025 Simplified)
# ============================================================
function gen_config {
    [ -z "$1" ] && echo "Usage: gen-config <config-file>" && return 1
    CONF_FILE=$1
    echo "Generating configuration for ID=$MYID..."

    # Get DPIDs cleanly
    OVS1_DPID="of:$(ovs-vsctl get bridge ovs1 datapath-id | tr -d '\"')"
    OVS2_DPID="of:$(ovs-vsctl get bridge ovs2 datapath-id | tr -d '\"')"
    
    # Try to find OVS3 (TA Switch)
    OVS3_DPID=$(curl -s -u onos:rocks http://localhost:8181/onos/v1/devices | \
        jq -r '.devices[].id' | grep -v "$OVS1_DPID" | grep -v "$OVS2_DPID" | head -n 1)

    if [ -z "$OVS3_DPID" ]; then
        echo "ERROR: OVS3 not found in ONOS. Abort."
        exit 1
    fi

    echo "DPIDS: OVS1=$OVS1_DPID, OVS2=$OVS2_DPID, OVS3=$OVS3_DPID"

    # --- FIXED FRR MAC DETECTION ---
    FRR_IF_FULL=$(docker exec frr ip -o link show | awk -F': ' '/vethovs1frr/ {print $2}' | head -n 1)
    FRR_IF=$(echo $FRR_IF_FULL | cut -d@ -f1)

    if [ -z "$FRR_IF" ]; then
        echo "CRITICAL ERROR: Could not find FRR interface inside container!"
        exit 1
    fi
    
    FRR_MAC=$(docker exec frr cat /sys/class/net/$FRR_IF/address)
    
    if [ -z "$FRR_MAC" ]; then
        echo "CRITICAL ERROR: Could not read MAC address for $FRR_IF"
        exit 1
    fi

    echo "Found FRR Interface: $FRR_IF"
    echo "Found FRR MAC: $FRR_MAC"
    
    AS65XX1_WAN_PORT=3
    AS65000_WAN_PORT=3
    FRR_CP="${OVS1_DPID}/2"

    cat > "$CONF_FILE" << EOF
{
  "ports": {
    "${OVS1_DPID}/${AS65XX1_WAN_PORT}": {
      "interfaces": [
        {
          "name": "ovs1 to AS65${MYID}1",
          "ips": [ "192.168.63.1/24", "fd63::1/64" ]
        }
      ]
    },
    "${OVS3_DPID}/${AS65000_WAN_PORT}": {
      "interfaces": [
        {
          "name": "ovs3 to AS65000",
          "ips": [ "192.168.70.253/24", "fd70::fe/64" ]
        }
      ]
    }
  },
  "apps": {
    "nycu.sdnfv.vrouter": {
      "router": {
        "frrouting-cp": "$FRR_CP",
        "frrouting-mac": "$FRR_MAC",
        "gateway-ip4": "172.16.$MYID.1",
        "gateway-ip6": "2a0b:4e07:c4:$MYID::1",
        "gateway-mac": "00:01:10:55:00:17",
        "wan-port-ip4": [ "192.168.70.$MYID", "192.168.63.1" ],
        "wan-port-ip6": [ "fd70::$MYID", "fd63::1" ],
        "v4-peer": [ "192.168.70.0/24", "192.168.63.0/24" ],
        "v6-peer": [ "fd70::/64", "fd63::/64" ]
      }
    }
  }
}
EOF
    echo "Configuration saved to $CONF_FILE"
}

# ============================================================
# CLEAN FUNCTION
# ============================================================
function clean {
    echo "Cleaning up environment..."
    
    # 1. Remove Containers
    remove_container $H1_CONTAINER
    remove_container $H2_CONTAINER
    remove_container $H3_CONTAINER
    remove_container $FRR_CONTAINER
    remove_container $R1_CONTAINER
    remove_container $ONOS_CONTAINER
    remove_container anycast1
    remove_container anycast2
    
    # 2. Delete Bridges
    ovs-vsctl del-br $OVS1 2>/dev/null || true
    ovs-vsctl del-br $OVS2 2>/dev/null || true
    
    # 3. Delete ALL specific veth pairs manually
    ip link del ${VETH_VXLANTA}0 2>/dev/null || true
    ip link del ${VETH_OVS1OVS2}0 2>/dev/null || true
    ip link del ${VETH_OVS2H1}0 2>/dev/null || true
    ip link del ${VETH_OVS2H2}0 2>/dev/null || true
    ip link del ${VETH_OVS1FRR}0 2>/dev/null || true  
    ip link del ${VETH_R1H3}0 2>/dev/null || true    
    ip link del ${VETH_OVS1R1}0 2>/dev/null || true   
    ip link del ${VETH_ANY1}0 2>/dev/null || true     
    ip link del ${VETH_ANY2}0 2>/dev/null || true     
    
    echo "Cleanup complete."
}

# ============================================================
# MAIN EXECUTION
# ============================================================
case $1 in
    "clean") clean ;;
    "deploy") deploy ;;
    "gen-config") shift; gen_config $@ ;;
    *) echo "Usage: $0 [deploy | clean | gen-config <output_file>]"; exit 1 ;;
esac

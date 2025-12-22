#!/bin/bash
set -e

# Team IDs for 2025 (3 students)
TEAMIDS="34 35 36"

if [ -z "$1" ]; then
    echo "Usage: ./team-config.sh <yourid>"
    echo "Available IDs: $TEAMIDS"
    exit 1
fi

MYID=$1

# Validate ID
if ! echo "$TEAMIDS" | grep -qw "$MYID"; then
    echo "Error: Invalid ID $MYID. Allowed: $TEAMIDS"
    exit 1
fi

# Calculate Peers automatically (exclude your own ID)
PEERS=()
for id in $TEAMIDS; do
    if [ "$id" != "$MYID" ]; then
        PEERS+=("$id")
    fi
done

PEER1=${PEERS[0]}
PEER2=${PEERS[1]}

echo "---------------------------------------"
echo "Configuring for Student ID: $MYID"
echo "Peers detected: $PEER1, $PEER2"
echo "2025 Mode: Peers connect via IXP AS65000 + direct VXLAN"
echo "---------------------------------------"

# Update topo_utils.sh
echo "Updating topo/topo_utils.sh..."
sed -i "s/PEERID=.*/PEERID=$PEER1/" topo/topo_utils.sh
sed -i "s/MYID=.*/MYID=$MYID/" topo/topo_utils.sh
sed -i "s/PEER2ID=.*/PEER2ID=$PEER2/" topo/topo_utils.sh

# Generate FRR configuration
echo "Generating FRR configuration..."
cat > topo/config/frr/frr.conf << EOF
!
! FRRouting configuration for AS65${MYID}0 (2025)
! Peers connect via IXP AS65000
!
frr defaults datacenter
ipv6 forwarding
!
! FPM connection to ONOS
fpm connection ip 192.168.100.1 port 2620
!
! Prefix Lists
ip prefix-list OWN_PREFIXES permit 172.16.${MYID}.0/24
ip prefix-list OWN_PREFIXES permit 172.17.${MYID}.0/24
!
ipv6 prefix-list OWN_PREFIXES_V6 permit 2a0b:4e07:c4:${MYID}::/64
ipv6 prefix-list OWN_PREFIXES_V6 permit 2a0b:4e07:c4:1${MYID}::/64
!
! BGP Configuration
router bgp 65${MYID}0
 bgp router-id 192.168.70.${MYID}
 timers bgp 60 180
 !
 ! Internal AS (AS65${MYID}1) - R1
 neighbor 192.168.63.2 remote-as 65${MYID}1
 neighbor 192.168.63.2 ebgp-multihop 255
 neighbor fd63::2 remote-as 65${MYID}1
 neighbor fd63::2 ebgp-multihop 255
 !
 ! IXP AS65000 - TA
 neighbor 192.168.70.253 remote-as 65000
 neighbor 192.168.70.253 ebgp-multihop 255
 neighbor 192.168.70.253 password winlab.nycu
 neighbor 192.168.70.253 solo
 neighbor fd70::fe remote-as 65000
 neighbor fd70::fe ebgp-multihop 255
 neighbor fd70::fe password winlab.nycu
 neighbor fd70::fe solo
 !
 ! IPv4 Address Family
 address-family ipv4 unicast
  network 172.16.${MYID}.0/24
  network 172.17.${MYID}.0/24
  neighbor 192.168.63.2 activate
  neighbor 192.168.70.253 activate
  no neighbor fd63::2 activate
  no neighbor fd70::fe activate
 exit-address-family
 !
 ! IPv6 Address Family
 address-family ipv6 unicast
  network 2a0b:4e07:c4:${MYID}::/64
  network 2a0b:4e07:c4:1${MYID}::/64
  neighbor fd63::2 activate
  neighbor fd70::fe activate
  no neighbor 192.168.63.2 activate
  no neighbor 192.168.70.253 activate
 exit-address-family
!
log stdout
!
line vty
!
EOF

# Generate R1 configuration (unchanged)
echo "Generating R1 configuration..."
cat > topo/config/r1/frr.conf << EOF
frr defaults datacenter
ipv6 forwarding
!
router bgp 65${MYID}1
 neighbor 192.168.63.1 remote-as 65${MYID}0
 neighbor fd63::1 remote-as 65${MYID}0
 !
 address-family ipv4 unicast
  network 172.17.${MYID}.0/24
  neighbor 192.168.63.1 activate
  no neighbor fd63::1 activate
 exit-address-family
 !
 address-family ipv6 unicast
  network 2a0b:4e07:c4:1${MYID}::/64
  neighbor fd63::1 activate
  no neighbor 192.168.63.1 activate
 exit-address-family
!
line vty
!
EOF

echo "---------------------------------------"
echo "Done! Configuration ready for ID $MYID"
echo ""
echo "2025 Network Summary:"
echo "  FRR IPs: 172.16.${MYID}.69, 192.168.63.1, 192.168.70.${MYID}, 192.168.100.3, 192.168.61.${MYID}"
echo "  BGP Neighbors: R1 (192.168.63.2), TA (192.168.70.253)"
echo "  VXLAN Peers: ${PEER1} and ${PEER2} via 192.168.61.x"
echo "---------------------------------------"

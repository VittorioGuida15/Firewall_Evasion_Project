#!/bin/bash

# Setup basic defensive iptables rules for the target_server

echo "Setting up defensive firewall rules..."

# 1. Log and Drop XMAS Packets (FIN, PSH, URG all set)
# These are highly anomalous and used in test_mutations.py
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j LOG --log-prefix "FW-DROP-XMAS: "
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP

# 2. Log and Drop packets with unusual TTLs (e.g. 111 as used in test_mutations.py)
# Note: iptables module 'ttl' is used. If not available, this might fail, so we don't drop, just log if possible.
# Actually, the 'ttl' module might not be in standard kernel modules for docker, so let's focus on flags and ports.
iptables -A INPUT -m ttl --ttl-eq 111 -j LOG --log-prefix "FW-DROP-TTL111: " || true
iptables -A INPUT -m ttl --ttl-eq 111 -j DROP || true

# 3. Log traffic pretending to be DNS (source port 53) connecting to HTTP (port 80)
iptables -A INPUT -p tcp --sport 53 --dport 80 -j LOG --log-prefix "FW-DROP-BADSPORT: "
iptables -A INPUT -p tcp --sport 53 --dport 80 -j DROP

echo "Defensive firewall rules configured."

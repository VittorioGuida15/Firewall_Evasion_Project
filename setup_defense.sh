#!/bin/bash
echo "Setting up defensive firewall rules..."
# Logga e scarta pacchetti XMAS (FIN, PSH, URG)
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j LOG --log-prefix "FW-DROP-XMAS: "
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
echo "Defensive firewall rules configured."
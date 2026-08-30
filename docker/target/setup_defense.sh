#!/bin/bash

# Setup basic defensive iptables rules for the target_server

echo "Setting up defensive firewall rules..."

# Logga e scarta pacchetti XMAS (FIN, PSH, URG)
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j LOG --log-prefix "FW-DROP-XMAS: "
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP

#Logga e scarta i pacchetti con valori TTL insoliti (es. 111)
iptables -A INPUT -m ttl --ttl-eq 111 -j LOG --log-prefix "FW-DROP-TTL111: " || true
iptables -A INPUT -m ttl --ttl-eq 111 -j DROP || true #true è per evitare che lo script vada in errore se il ttl non è settato

# Logga e scarta il traffico che finge di essere DNS (porta sorgente 53) e che tenta di connettersi al server web (porta di destinazione 80)
iptables -A INPUT -p tcp --sport 53 --dport 80 -j LOG --log-prefix "FW-DROP-BADSPORT: "
iptables -A INPUT -p tcp --sport 53 --dport 80 -j DROP

echo "Defensive firewall rules configured."
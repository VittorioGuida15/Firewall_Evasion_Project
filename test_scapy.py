from scapy.all import IP, TCP

ip_layer = IP(dst="8.8.8.8")

tcp_layer = TCP(dport=80, flags="S")

pocket = ip_layer / tcp_layer

print("Struttura del pacchetto")
pocket.show()

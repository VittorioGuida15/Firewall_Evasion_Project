from scapy.all import IP, TCP, Raw

#Pacchetto di base
ip_layer = IP(dst="8.8.8.8")
tcp_layer = TCP(dport=80, flags="S")
pocket = ip_layer / tcp_layer
print("Struttura del pacchetto")
pocket.show()

#Modifica pacchetto
pocket[IP].ttl = 128
pocket[TCP].window = 4096
pocket[TCP].flags = "PA" # Cambiamo i flag in PSH+ACK (invio dati)

#Aggiunta payload HTTP con uno User-Agent camuffato (imitare servizi fidati)
http_request = "GET / HTTP/1.1\r\nHost: 8.8.8.8\r\nUser-Agent: Windows-Update-Agent\r\n\r\n"

mutated_packet = pocket / Raw(load=http_request)

print("Pacchetto mutato")
mutated_packet.show()



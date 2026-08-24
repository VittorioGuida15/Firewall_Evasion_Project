from scapy.all import IP, TCP, Raw, send

#Pacchetto di base
ip_layer = IP(dst="target_server")
tcp_layer = TCP(dport=80, flags="S")
packet = ip_layer / tcp_layer
print("Struttura del pacchetto")
packet.show()

#Modifica pacchetto
packet[IP].ttl = 128
packet[TCP].window = 4096
packet[TCP].flags = "PA" # Cambiamo i flag in PSH+ACK (invio dati)

#Aggiunta payload HTTP con uno User-Agent camuffato (imitare servizi fidati)
http_request = "GET / HTTP/1.1\r\nHost: target_server\r\nUser-Agent: Windows-Update-Agent\r\n\r\n"

mutated_packet = packet / Raw(load=http_request)

print("Pacchetto mutato")
mutated_packet.show()

print("Invio del pacchetto mutato...")
send(mutated_packet)
print("Pacchetto inviato!")


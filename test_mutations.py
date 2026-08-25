from scapy.all import IP, TCP
from mutation_engine import mutate_ip_ttl, mutate_tcp_flags, mutate_source_port, fragment_ip_packet

print("Creazione pacchetto di base:")
packet = IP(dst="target_server") / TCP(dport=80, flags="S")
packet.show()

print("Mutazione")
packet = mutate_ip_ttl(packet, 111)
packet = mutate_tcp_flags(packet, "FPU") 
packet = mutate_source_port(packet, 53)  # Mascherato come traffico DNS in uscita
packet.show()

print("Frammentazione:")
fragments = fragment_ip_packet(packet, 16)
for i, frag in enumerate(fragments):
    print(f"\nFrammento {i+1}:")
    frag.show()
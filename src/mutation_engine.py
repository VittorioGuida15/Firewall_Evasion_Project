from scapy.all import IP, TCP, Raw, fragment

def mutate_ip_ttl(packet, new_ttl):
    """Modifica il Time To Live del pacchetto IP."""
    if packet.haslayer(IP):
        packet[IP].ttl = new_ttl
    return packet

def mutate_tcp_window_size(packet, new_size):
    """Modifica le dimensioni della finestra TCP."""
    if packet.haslayer(TCP):
        packet[TCP].window = new_size
    return packet

def mutate_tcp_flags(packet, new_flags):
    """Altera i flag TCP"""
    if packet.haslayer(TCP):
        packet[TCP].flags = new_flags
    return packet

def mutate_source_port(packet, new_port):
    """Cambia la porta di origine"""
    if packet.haslayer(TCP):
        packet[TCP].sport = new_port
    return packet

def fragment_ip_packet(packet, frag_size=8):
    """
    Spezza il pacchetto IP in frammenti più piccoli (Solo multipli di 8)
    ATTENZIONE: Questa funzione restituisce una LISTA di pacchetti, non uno singolo.
    """
    if packet.haslayer(IP):
        return fragment(packet, fragsize=frag_size)
    return [packet]

def mutate_http_header(packet, new_user_agent):
    """
    Sovrascrive il payload Raw con una nuova richiesta HTTP mascherata.
    """
    http_request = f"GET / HTTP/1.1\r\nHost: target_server\r\nUser-Agent: {new_user_agent}\r\n\r\n"
    if packet.haslayer(Raw):
        packet[Raw].load = http_request
    else: 
        # Se non c'è payload, lo aggiunge
        packet = packet / Raw(load=http_request)
    return packet
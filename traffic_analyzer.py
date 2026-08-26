import time
from collections import Counter
from scapy.all import IP, TCP, sr1, sniff

def send_standard_http_request():
    """Invia una richiesta HTTP standard per simulare traffico normale."""
    ip_layer = IP(dst="target_server")
    tcp_layer = TCP(dport=80, flags="S")
    packet = ip_layer / tcp_layer
    print("Invio richiesta baseline...")
    response = sr1(packet, timeout=2, verbose=0)
    return response

def analyze_traffic_baseline(duration=10):
    """Cattura il traffico per un tempo determinato e ne analizza le statistiche di base."""
    print(f"Cattura traffico per {duration} secondi per stabilire la baseline...")
    packets = sniff(filter="tcp and port 80", timeout=duration)

    if not packets:
        print("Nessun pacchetto catturato. Assicurati che target_server sia raggiungibile.")
        return

    packet_sizes = []
    ttl_values = []
    tcp_flags_counter = Counter()

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            packet_sizes.append(len(pkt))
            ttl_values.append(pkt[IP].ttl)
            # Converte il valore flag in stringa leggibile
            flags = pkt.sprintf('%TCP.flags%')
            tcp_flags_counter[flags] += 1

    avg_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
    avg_ttl = sum(ttl_values) / len(ttl_values) if ttl_values else 0

    print("\n--- Baseline Profile ---")
    print(f"Pacchetti analizzati: {len(packets)}")
    print(f"Dimensione media pacchetto: {avg_size:.2f} bytes")
    print(f"TTL medio: {avg_ttl:.2f}")
    print("Distribuzione Flag TCP:")
    for flag, count in tcp_flags_counter.items():
         print(f"  {flag}: {count}")
    print("------------------------\n")

if __name__ == "__main__":
    # Invia qualche richiesta per generare traffico se non c'è nulla in esecuzione
    send_standard_http_request()
    analyze_traffic_baseline(duration=5)

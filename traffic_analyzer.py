import time
import json
from collections import Counter
from scapy.all import IP, TCP, sr1, sniff

def analyze_traffic_baseline(duration=20):
    """Cattura il traffico per un tempo determinato e ne analizza le statistiche di base."""
    print(f"Cattura traffico per {duration} secondi per stabilire la baseline...")
    packets = sniff(filter="tcp and port 80", timeout=duration)

    if not packets:
        print("Nessun pacchetto catturato. Assicurati di generare traffico da un altro terminale.")
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

    baseline_data = {
        "avg_packet_size": round(avg_size, 2),
        "avg_ttl": round(avg_ttl, 2),
        "tcp_flags_distribution": dict(tcp_flags_counter)
    }

    # Salviamo i dati in un file JSON (il nostro "Baseline Profile DB" del PoC)
    with open("baseline.json", "w") as f:
        json.dump(baseline_data, f, indent=4)

    print("\n--- Baseline Profile ---")
    print(f"Pacchetti analizzati: {len(packets)}")
    print(f"Dimensione media pacchetto: {avg_size:.2f} bytes")
    print(f"TTL medio: {avg_ttl:.2f}")
    print("Distribuzione Flag TCP:")
    for flag, count in tcp_flags_counter.items():
         print(f"  {flag}: {count}")
    print("------------------------\n")
    print("Profilo Baseline salvato correttamente in baseline.json")

if __name__ == "__main__":
    # Si mette semplicemente in ascolto (approccio a due terminali)
    print("In attesa di traffico...")
    analyze_traffic_baseline(duration=20)

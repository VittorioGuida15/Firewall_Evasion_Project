import time
import json
from collections import Counter
from scapy.all import IP, TCP, sr1, sniff

def analyze_traffic_baseline(duration=20):
    """Cattura il traffico per un tempo determinato e ne analizza le statistiche di base facendone la media."""
    print(f"cattura il traffico per {duration} secondi")
    packets = sniff(filter="tcp and port 80", timeout=duration)

    if not packets:
        print("Nessun pacchetto catturato")
        return

    #Estrazione caratteristiche dei pacchetti
    packet_size = []
    ttl_values = []
    tcp_flags_counter = Counter()

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            packet_size.append(len(pkt))
            ttl_values.append(pkt[IP].ttl)
            flags = pkt.sprintf('%TCP.flags%') #Converte flag in stringa
            tcp_flags_counter[flags] += 1

    #Calcolo media del profilo baseline
    avg_size = 0
    avg_ttl = 0
    if packet_size:
        avg_size = sum(packet_size) / len(packet_size)
    if ttl_values:
        avg_ttl = sum(ttl_values) / len(ttl_values)

    #Organizzazione dei dati
    baseline_data = {
            "avg_packet_size": round(avg_size, 2),
            "avg_ttl": round(avg_ttl, 2),
            "tcp_flags_distribution": dict(tcp_flags_counter)
    }

    #Salvataggio dati in file JSON
    with open("baseline.json", "w") as f:
            json.dump(baseline_data, f, indent=4) #indent: indentazione file JSON


    print("\n Profilo Baseine")
    print(f"Pacchetti analizzati: {len(packets)}")
    print(f"Dimensione media pacchetto: {avg_size:.2f} bytes")
    print(f"TTL medio: {avg_ttl:.2f}")
    print("Distribuzione Flag TCP:")
    for flags, count in tcp_flags_counter.items():
        print(f" {flags}: {count}")
    print("------------------------\n")
    print("Profilo Baseline salvato in baseline.json")

if __name__ == "__main__":
    print("In attesa di traffico...")
    analyze_traffic_baseline(duration=20)


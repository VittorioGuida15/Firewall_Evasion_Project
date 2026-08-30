import time
import json
import os
from scapy.all import IP, TCP, sr1
from mutation_engine import mutate_tcp_flags

def log_evasion_attempt(packet_type, score):
    log_entry = {
        "timestamp": time.time(),
        "packet_type": packet_type,
        "score": score
    }

    logs = []
    if os.path.exists("evasion_log.json"):
        with open("evasion_log.json", "r") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                # If file exists but is empty or invalid, start fresh
                logs = []

    logs.append(log_entry)

    with open("evasion_log.json", "w") as f:
        json.dump(logs, f, indent=4)

def run_evasion_loop():
    print("--- Inizio Evasion Loop (Orchestratore) ---")

    # Pacchetto Base Malevolo (verrà bloccato)
    # È un pacchetto XMAS (FIN, PSH, URG)
    ip_layer = IP(dst="target_server")
    tcp_layer = TCP(dport=80, flags="FPU")
    packet = ip_layer / tcp_layer

    print("\n[Fase 1] Invio pacchetto base malevolo (XMAS) senza mutazioni...")
    response = sr1(packet, timeout=3, verbose=0)

    score = evaluate_response(response)
    log_evasion_attempt("XMAS_base", score)

    if score == -1:
        print("\n[Fase 2] Il pacchetto è stato bloccato. Applicazione mutazione (Cambio Flag TCP a SYN)...")
        # Mutiamo il pacchetto togliendo i flag anomali
        mutated_packet = mutate_tcp_flags(packet, "S")

        print("Ritento l'invio con il pacchetto mutato...")
        response2 = sr1(mutated_packet, timeout=3, verbose=0)
        score2 = evaluate_response(response2)
        log_evasion_attempt("SYN_mutation", score2)

        if score2 == 1:
             print("\n[SUCCESSO] La mutazione ha bypassato il firewall! (Score: +1)")
        else:
             print("\n[FALLIMENTO] Anche la mutazione è stata bloccata. (Score: -1)")

    elif score == 1:
        print("\n[ATTENZIONE] Il pacchetto base non è stato bloccato. Controlla le regole del firewall.")

def evaluate_response(response):
    """Valuta la risposta del firewall/server e restituisce un punteggio."""
    if response is None:
        print("-> Esito: Nessuna risposta (probabilmente scartato - DROP). Score: -1")
        return -1
    elif response.haslayer(TCP):
        if response[TCP].flags == "SA": # SYN-ACK
            print("-> Esito: Risposta SYN-ACK (Connessione accettata). Score: +1")
            return 1
        elif response[TCP].flags in ["R", "RA"]: # RST
            print("-> Esito: Connessione rifiutata attivamente (RST). Score: -1")
            return -1
    print("-> Esito: Risposta anomala o non gestita. Score: -1")
    return -1

if __name__ == "__main__":
    run_evasion_loop()

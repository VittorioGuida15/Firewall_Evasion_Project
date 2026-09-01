import time
import json
import os
from scapy.all import IP, TCP, sr1
from mutation_engine import mutate_tcp_flags
from successFeedbackAnalyzer import evaluate_response

def log_evasion_attempt(packet_time, score):
    """Salva la risposta del firewall e il punteggio del tentativo nel file JSON."""
    #Organizzazione dei dati
    log_entry = {
        "timestamp": time.time(),
        "packet_type": packet_time, #Etichetta mutazione applicata
        "score": score
    }

    logs = []

    if os.path.exists("evasion_log.json"): 
        with open("evasion_log.json", "r") as f:
            try:
                logs = json.load(f) #Se il file esiste, prendi il contenuto
            except json.JSONDecodeError:
                logs = [] #Se esiste ma è vuoto o invalido, reset

    logs.append(log_entry)

    #Salvataggio dati in file JSON
    with open("evasion_log.json", "w") as f:
        json.dump(logs, f, indent=4) #indent: indentazione file JSON
        
def run_evasion_loop():
    print("\n[Fase 1] Inizio Evasion Loop (Orchestratore)...")

    #pacchetto anomalo XMAS
    ip_layer = IP(dst="target_server")
    tcp_layer = TCP(dport=80, flags="FPU")
    packet = ip_layer / tcp_layer

    print("Invio pacchetto anomalo (XMAS) senza mutazioni")
    response = sr1(packet, timeout=3, verbose=0) #verbose = 0: lavora in background

    #Valutazione risposte
    score = evaluate_response(response)
    log_evasion_attempt("XMAS_base", score)

    #Evasione
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


if __name__ == "__main__":
    run_evasion_loop()



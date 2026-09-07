import time
import json
import os
from scapy.all import IP, TCP, sr1
from mutation_engine import mutate_tcp_flags, mutate_ip_ttl, mutate_tcp_window_size, mutate_source_port
import llm_engine

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

    current_score = score
    current_packet = packet

    # Evasion Loop (max 5 tentativi per PoC)
    for attempt in range(1, 6):
        if current_score == 1:
            print(f"\n[SUCCESSO] Bypass del firewall riuscito dopo {attempt-1} mutazioni! Interruzione ciclo.")
            break

        print(f"\n[Fase 2 - Tentativo {attempt}] Il pacchetto è stato bloccato. Richiesta mutazione al Mock LLM...")

        # 1. Chiediamo al Mock LLM come mutare il pacchetto, passandogli il feedback precedente
        mock_llm_response_json = llm_engine.get_mock_llm_mutation(previous_score=current_score)
        mock_response = json.loads(mock_llm_response_json)

        print(f"-> Ragionamento LLM simulato: {mock_response['reasoning']}")
        mutation_details = mock_response['mutation']
        mutation_type = mutation_details['mutation_type']
        mutation_value = mutation_details['value']

        print(f"-> Applicazione mutazione: {mutation_type} con valore: {mutation_value}")

        # 2. Applichiamo la mutazione usando il motore di mutazione
        mutated_packet = current_packet.copy() # Lavoriamo su una copia per non sovrascrivere l'originale
        if mutation_type == "mutate_tcp_flags":
            mutated_packet = mutate_tcp_flags(mutated_packet, mutation_value)
        elif mutation_type == "mutate_ip_ttl":
            mutated_packet = mutate_ip_ttl(mutated_packet, mutation_value)
        elif mutation_type == "mutate_tcp_window_size":
            mutated_packet = mutate_tcp_window_size(mutated_packet, mutation_value)
        elif mutation_type == "mutate_source_port":
            mutated_packet = mutate_source_port(mutated_packet, mutation_value)
        else:
            print("-> Tipo di mutazione non riconosciuto dal Mock LLM.")

        # 3. Inviamo il pacchetto mutato e valutiamo la risposta
        print("-> Invio pacchetto mutato...")
        response2 = sr1(mutated_packet, timeout=3, verbose=0)
        current_score = evaluate_response(response2)
        current_packet = mutated_packet # Aggiorniamo il pacchetto corrente per la prossima iterazione

        # Log del tentativo
        log_name = f"Mock_LLM_Attempt_{attempt}_{mutation_type}_{mutation_value}"
        log_evasion_attempt(log_name, current_score)

        if current_score == -1:
             print("-> [FALLIMENTO] Anche questo pacchetto mutato è stato bloccato.")

    if current_score == -1:
        print("\n[FINE] Limite di tentativi raggiunto. L'evasione è fallita per questo ciclo.")

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

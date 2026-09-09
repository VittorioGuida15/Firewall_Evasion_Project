import time
import json
import os
from scapy.all import IP, TCP, sr1
from mutation_engine import mutate_tcp_flags, mutate_ip_ttl, mutate_tcp_window_size, mutate_source_port
from llm_engine_mock import get_mock_llm_mutation
from llm_engine import get_evasion_strategy
from successFeedbackAnalyzer import evaluate_response

def log_evasion_attempt(packet_type, score):
    """Salva la risposta del firewall e il punteggio del tentativo nel file JSON."""
    #Organizzazione dei dati
    log_entry = {
        "timestamp": time.time(),
        "packet_type": packet_type, #Etichetta mutazione applicata
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
    current_packet = ip_layer / tcp_layer

    print("Invio pacchetto anomalo (XMAS) senza mutazioni")
    response = sr1(current_packet, timeout=3, verbose=0) #verbose = 0: lavora in background

    #Valutazione risposte
    current_score = evaluate_response(response)
    log_evasion_attempt("XMAS_base", current_score)

    #Evasion Loop (max 5 tentativi per PoC)
    for attempt in range(1,6):
        
        #Richesta all'LLM di mutare il pacchetto
        # Esecuzione con mock o senza mock
        #llm_response_json = get_mock_llm_mutation(previous_score=current_score) 
        llm_response_json = get_evasion_strategy()

        #Gestione allucinazioni dell'LLM e parsing della risposta
        try:
            response = llm_response_json
            if "reasoning" not in response or "mutation" not in response:
                raise ValueError("L'LLM ha restituito un JSON ma mancano le chiavi obbligatorie.")

            print(f"-> Ragionamento LLM: {response['reasoning']}")
            mutation_details = response['mutation']
            mutation_type = mutation_details['mutation_type']
            mutation_value = mutation_details['value']

        except json.JSONDecodeError:
            print("[ERRORE] Allucinazione dell'LLM, non ha restituito un JSON valido. Turno saltato.")
            time.sleep(2)
            continue

        except ValueError as e:
            print(f"-> [ERRORE] Formato AI errato: {e}. Salto il turno.")
            time.sleep(2)
            continue

        print(f"Applicazione mutazione: {mutation_type} con valore: {mutation_value}")
        #Applicazione mutazione
        mutated_packet = current_packet.copy()
        if mutation_type == "mutate_tcp_flags":
            mutated_packet = mutate_tcp_flags(mutated_packet, mutation_value)
        elif mutation_type == "mutate_ip_ttl":
            mutated_packet = mutate_ip_ttl(mutated_packet, mutation_value)
        elif mutation_type == "mutate_tcp_window_size":
            mutated_packet = mutate_tcp_window_size(mutated_packet, mutation_value)
        elif mutation_type == "mutate_source_port":
            mutated_packet = mutate_source_port(mutated_packet, mutation_value)
        else:
            print("-> Tipo di mutazione non riconosciuta.")

        #invio pacchetto mutato e valutazione risposta
        print("-> Invio pacchetto mutato...")
        response2 = sr1(mutated_packet, timeout=3, verbose=0)
        current_score = evaluate_response(response2)
        current_packet = mutated_packet #Aaggiorna il pacchetto corrente per il prossimo tentativo.

        #Scrittura log del tentativo
        log_packet_type = f"LLM_Attempt_{attempt}_{mutation_type}_{mutation_value}"
        log_evasion_attempt(log_packet_type, current_score)

        if current_score == 1:
            print(f"\n[SUCCESSO] Bypass del firewall riuscito al tentativo {attempt}! Interruzione ciclo.")
            break
        else:
            print("\n[Fallimento] Il pacchetto mutato è stato bloccato dal firewall.")
            # Rate limiting
            print("Attesa di 2 secondi prima del prossimo tentativo...")
            time.sleep(2)

    if current_score == -1:
        print("\n[FINE] Limite di tentativi raggiunto. L'evasione è fallita per questo ciclo.")


if __name__ == "__main__":
    run_evasion_loop()



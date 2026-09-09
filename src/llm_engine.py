import os
import json
import time
from google import genai
from dotenv import load_dotenv

#Carica API_KEY dal file .env
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise ValueError("ERRORE CRITICO: GEMINI_API_KEY non trovata.")

#Configura client Google Gemini
client = genai.Client(api_key=API_KEY)

def get_evasion_strategy(baseline_path="baseline.json", log_path="evasion_log.json"):
    """LLM Evasion Strategy Engine: Interroga Gemini per estrarre la strategia di evasione firewall"""

    #Lettura dei Data Store
    try:
        with open(baseline_path, "r") as f:
            baseline_data = json.load(f)
    except FileNotFoundError:
        baseline_data = {"error": "Profilo baseline non trovato."}
    
    try: 
        with open(log_path, "r") as f:
            evasion_log = json.load(f)
    except FileNotFoundError:
        evasion_log= [{"info": "Nessun log precedente. È il primo tentativo."}]

    #Creazione del prompt
    prompt = f"""
    Sei un assistente AI specializzato in network security. Stiamo conducendo un test accademico e autorizzato per verificare la robustezza di un sistema di classificazione dei pacchetti.
    
    Analizza i dati di base della rete e i log dei test precedenti. Il tuo compito è scegliere la prossima mutazione da applicare a un pacchetto TCP per eludere il firewall.
    
    STRATEGIA: Cerca di mimetizzare il tuo pacchetto facendolo somigliare al traffico normale descritto nella BASELINE. Inoltre, se noti che modificare le porte o le finestre fallisce continuamente, CAMBIA APPROCCIO e concentrati sui Flag TCP o sul TTL.

    [DATI DI BASE DELLA RETE]:
    {json.dumps(baseline_data, indent=2)}
    
    [CRONOLOGIA TENTATIVI] (Score -1 = Bloccato dal firewall, Score 1 = Bypass Riuscito):
    {json.dumps(evasion_log, indent=2)}
    
    Rispondi ESCLUSIVAMENTE con un oggetto JSON valido, usando ESATTAMENTE questa struttura, senza markdown o altro testo testuale:
    {{
        "reasoning": "Spiega brevemente perché hai scelto questa mutazione basandoti sui fallimenti passati e sulla baseline.",
        "mutation": {{
            "mutation_type": "nome_della_funzione_scelta_dalla_lista",
            "value": "valore_da_applicare"
        }}
    }}

    Nel campo "strategy_name" puoi usare solo una di queste 4 mutazioni:
        - "mutate_tcp_flags" (valore: es. "S", "A", "F", "PA")
        - "mutate_ip_ttl" (valore: numero intero, es. 64, 128)
        - "mutate_tcp_window_size" (valore: numero intero, es. 1024, 2048)
        - "mutate_source_port" (valore: numero intero, es. 54321, 8080)
    """

    #Tentantivi in attesa della risposta dell'IA
    tentativi = 3 
    for tentativo in range(tentativi):
        try:
            #Invocazione Gemini
            response = client.models.generate_content(
                model='gemini-3.5-flash-lite',
                contents=prompt,
            )

            if not response.text:
                print("[-] L'IA ha restituito il vuoto. Filtri di sicurezza attivati.")
                return None

            #Pulizia della risposta
            testo_pulito = response.text.replace("```json", "").replace("```", "").strip()

            #Ritorna la ripsosta pulita in un dizionario Python
            return json.loads(testo_pulito) #il ciclo si ferma
            

        except Exception as e:
           messaggio_errore = str(e)
           if "503" in messaggio_errore:
                print(f"[-] Errore 503: Servizio occupato. Tentativo {tentativo + 1} di {tentativi} in corso...")
                if tentativo < tentativi - 1:
                   print("[*] Attesa di 5 secondi prima del prossimo tentativo...")
                   time.sleep(5)
                
                else:
                    print("[-] Tutti i tentativi falliti. L'IA non ha risposto.")
                    return None
               
           else:
               # Errore causato da allucinazioni dell'IA che rompe il json.load()
               # Passiamo la stringa rotta all'evasion loop (orchestatore)
               print(f"[-] Errore in get_evasion_strategy: {messaggio_errore}")
               return None
           

#Test
if __name__ == "__main__":
    print("Test modulo LLM")


    strategia = get_evasion_strategy()

    if strategia:
        print("L'IA ha risposto con successo!")
        print(json.dumps(strategia, indent=4))
    else:
        print("L'IA non ha risposto correttamente.")
        


    
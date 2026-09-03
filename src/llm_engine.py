import os
import json
import google.generativeai as genai
from dotenv import load_dotenv

#Carica API_KEY dal file .env
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise ValueError("ERRORE CRITICO: GEMINI_API_KEY non trovata.")

#Configura libreria Google con API_KEY
genai.configure(api_key=API_KEY)

def get_evasion_strategy(baseline_path="baseline.json", log_path="evasion_log.json"):
    """LLM Evasion Strategy Engine: Interroga Gemini per estrarre la strategia di evasione firewall"""

    #Lettura dei Data Store
    try:
        with open(baseline_path, "r") as f:
            baseline_data = json.load(f)
    except FileExistsError:
        baseline_data = {"error": "Profilo baseline non trovato."}
    
    try: 
        with open(log_path, "r") as f:
            evasion_log = json.load(f)
    except FileExistsError:
        evasion_log= [{"info": "Nessun log precedente. È il primo tentativo."}]

#Creazione del prompt
    prompt = f"""
    Sei un esperto di cybersecurity e il 'Cervello' di un sistema automatizzato di Evasione Firewall.
    Il tuo compito è analizzare il traffico di base della rete e la cronologia dei tentativi falliti/riusciti, per suggerire la prossima mutazione.

    [DATI DI BASE DELLA RETE] (Come appare il traffico normale):
    {json.dumps(baseline_data, indent=2)}

    [CRONOLOGIA TENTATIVI] (Score -1 = Bloccato, Score 1 = Passato):
    {json.dumps(evasion_log, indent=2)}

    Attualmente il nostro motore Python può modificare i flag TCP.
        Il tuo compito è mimetizzarti nel traffico normale per bypassare i blocchi.
        
        DEVI rispondere ESCLUSIVAMENTE con un oggetto JSON valido in questo formato esatto, senza aggiungere formattazione markdown o altro testo:
        {{
                "strategy_name": "Nome_Inventato_Da_Te_Per_Questa_Strategia",
                "target_flags": "I_FLAG_CHE_SUGGERISCI_DI_USARE",
                "reasoning": "Spiega in una frase perché hai scelto questi flag"
            }}
    """

    #Invocazione Gemini
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(prompt)

        #Pulizia della risposta
        testo_pulito = response.text.replace("```json", "").replace("```", "").strip()

        #Converte la ripsosta pulita in un dizionario Python
        strategia = json.loads(testo_pulito)
        return strategia

    except Exception as e:
        print(f"[-] Errore di comunicazione con l'IA: {e}")
        return None

#Test
if __name__ == "__main":
    print("Avvio LLM Evasion Strategy Engine...")
    print("Contatto i server di Google Gemini in corso...\n")

    nuova_strategia = get_evasion_strategy()

    if nuova_strategia:
        print("L'IA ha risposto con successo!")
        print(json.dumps(nuova_strategia, indent=4))
        


    
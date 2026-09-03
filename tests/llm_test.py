import os
import google.generativeai as genai

#Configurazione della chiave API
api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    print("Errore: Variabile d'ambiente GEMINI_API_KEY non trovata.")
    exit()

#Configura il client con la chiave API
genai.configure(api_key=api_key)

#Scelta del Modello
model = genai.GenerativeModel('gemini-1.5-flash')

#Preparazione del Prompt
prompt = "Spiegami in 3 righe come funziona il protocollo TCP."

#Invocazione dell'API
try:
    print("Inviando la richiesta a Gemini...")
    response = model.generate_content(prompt)
    
    # 5. Stampa del risultato
    print("\nRisposta di Gemini:")
    print(response.text)
    
except Exception as e:
    print(f"Si è verificato un errore di comunicazione: {e}")
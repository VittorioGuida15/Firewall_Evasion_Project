import os
from dotenv import load_dotenv
from google import genai

# Caricamento variabili
load_dotenv()
api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    print("Errore: Variabile d'ambiente GEMINI_API_KEY non trovata.")
    exit()

#configurazione del client
client = genai.Client(api_key=api_key)

print("[*] Interrogo Gemini...")

#Chiamata al modello
response = client.models.generate_content(
    model='gemini-3.6-flash',
    contents="Spiegami in 3 righe come funziona il protocollo TCP."
)

print("\n[+] Risposta di Gemini:")
print(response.text)
# 🛡️ AI-Driven Firewall Evasion System

**AI-Driven Firewall Evasion System** è un Proof of Concept (PoC) sviluppato per dimostrare come l'Intelligenza Artificiale possa essere utilizzata per automatizzare tecniche di elusione dei controlli di rete. Questo progetto funge da base per la prima parte di una Tesi Magistrale in Sicurezza Informatica, esplorando l'integrazione di LLM (Large Language Models) nell'analisi del feedback dei firewall e nell'orchestrazione di mutazioni di pacchetti a livello di rete.

Attualmente, il sistema utilizza un motore "Mock" per simulare le decisioni dell'AI, permettendo di testare e validare l'intero ciclo di orchestrazione (invio, blocco, analisi, mutazione) in un ambiente controllato prima dell'integrazione completa con le API reali (es. Google Gemini).

---

## 🧩 Funzionalità principali
*   **Orchestratore Autonomo:** Loop di esecuzione che invia automaticamente pacchetti anomali e analizza la risposta del firewall.
*   **Motore di Mutazione (`mutation_engine.py`):** Modifica dinamica di pacchetti di rete tramite Scapy (TCP Flags, TTL, Window Size, Source Port).
*   **Simulatore LLM (`llm_engine.py`):** Modulo "Mock" che simula l'analisi di un'AI, fornendo un ragionamento fittizio e suggerendo mutazioni in formato JSON.
*   **Logging Strutturato:** Salvataggio automatico di storici e baseline in formato JSON, pronti per essere elaborati da un LLM reale.
*   **Resilienza e Rate Limiting:** Gestione avanzata degli errori (allucinazioni AI) e controllo dei rate limit delle API per garantire la stabilità dell'orchestratore.
*   **Ambiente Dockerizzato:** Containerizzazione completa di Attaccante e Target (Nginx + Iptables) per test sicuri e isolati senza impattare l'host.

---

## 📁 Struttura del progetto
```text
Firewall_Evasion_Project/
├── .gitignore                  → File e cartelle ignorate da Git
├── README.md                   → Documentazione del progetto (questo file)
├── requirements.txt            → Dipendenze Python (scapy, google-genai, python-dotenv)
├── docker-compose.yml          → Configurazione per avviare l'infrastruttura di test
│
├── src/                        → Logica principale dell'Attaccante
│   ├── evasion_loop.py         → L'orchestratore principale (loop di test e mutazioni)
│   ├── llm_engine.py           → Il Mock che simula le risposte in formato JSON dell'LLM
│   ├── mutation_engine.py      → Libreria di funzioni Scapy per mutare i pacchetti
│   └── traffic_analyzer.py     → Sniffer passivo per generare la baseline.json
│
├── tests/                      → File di test e validazione
│   ├── llm_test.py             → Script isolato per testare la connessione reale a Gemini API
│   ├── test_mutations.py       → Unit test per il motore di mutazione
│   ├── test_scapy.py           → Test di base per la sintassi Scapy
│   └── test_SuccessFeedbackAnalyzer.py → Test per la logica di valutazione delle risposte TCP
│
├── docker/                     → Configurazione degli ambienti isolati
│   ├── attacker/
│   │   └── Dockerfile.attacker → Immagine per l'esecuzione degli script Python (con permessi NET_ADMIN)
│   └── target/
│       ├── Dockerfile.target   → Immagine server web Nginx
│       └── setup_defense.sh    → Script di configurazione delle regole Iptables (Firewall)
│
└── data/ (Generati dinamicamente)
    ├── evasion_log.json        → Storico incrementale di tutti i tentativi e relativi esiti
    └── baseline.json           → Modello del traffico normale generato dal traffic_analyzer
```

---

## 🛠️ Requisiti
*   **Docker Desktop** (o Docker Engine + Docker Compose)
*   **Python 3.10+** (per eventuali esecuzioni locali, anche se l'uso di Docker è raccomandato per i permessi di rete)
*   *(Futuro)*: API Key di Google Gemini (per l'integrazione della fase 2).

---

## ⚙️ Setup del progetto

1. **Clona il repository:**
   ```bash
   git clone https://github.com/TuoUtente/Firewall_Evasion_Project.git
   cd Firewall_Evasion_Project
   ```

2. **Costruisci i container Docker:**
   Questo passaggio creerà le immagini sia per il server target (con Nginx e regole Iptables rigide) sia per l'ambiente attaccante (con Python e Scapy installati).
   ```bash
   docker-compose build
   ```

---

## 🚀 Avvio del progetto

Il progetto prevede l'uso di due container in esecuzione simultanea sulla stessa rete Docker isolata.

### 💻 Avvio dell'Infrastruttura (Target)
Apri un terminale e avvia i container in background. Il container `target_server` si avvierà, eseguirà lo script `setup_defense.sh` (configurando Iptables per bloccare pacchetti anomali) ed esporrà la porta 80.
```bash
docker-compose up -d
```

### 💻 Accesso al Container Attaccante
Per eseguire gli script che manipolano il traffico raw di rete (Scapy), è necessario operare direttamente all'interno del container attaccante, che gode del privilegio `NET_ADMIN`.
Apri un nuovo terminale ed entra nel container:
```bash
docker exec -it attacker_client bash
```

### 🧪 Esecuzione del Test di Evasione (PoC)
All'interno del container `attacker_client`, puoi ora lanciare l'orchestratore. Il programma tenterà di inviare un pacchetto malevolo, verrà bloccato, chiederà istruzioni al Mock LLM e applicherà mutazioni cicliche.
```bash
python evasion_loop.py
```
*I risultati e il ragionamento dell'AI verranno stampati a schermo, e il file `evasion_log.json` verrà aggiornato ad ogni iterazione.*

---

## 🧠 Flusso di esecuzione (Architettura)

1. **Fase Iniziale (Paziente Zero):** L'orchestratore (`evasion_loop.py`) genera e invia un pacchetto di rete palesemente anomalo (TCP XMAS) verso il `target_server`.
2. **Valutazione del Firewall:** Il firewall (Iptables) del server bersaglio analizza il pacchetto. Poiché viola le regole basilari, viene scartato (DROP) senza inviare risposta. L'orchestratore registra il fallimento (Score: -1).
3. **Analisi e Risoluzione AI (Mock):** L'orchestratore interroga il modulo `llm_engine.py`. Attualmente, questo componente simula un modello linguistico avanzato, restituendo un JSON che contiene un "ragionamento" tattico fittizio e i dettagli esatti della mutazione suggerita (es. Cambiare TTL a 128 o impostare il flag su SYN).
4. **Applicazione della Mutazione:** Il `mutation_engine.py` riceve le istruzioni via JSON, altera il pacchetto in memoria e lo re-invia al bersaglio.
5. **Esito e Logging:**
    * Se il pacchetto passa (Score: +1), il ciclo si interrompe segnalando il successo.
    * Se viene bloccato (Score: -1), il ciclo si ripete per un massimo di 5 tentativi.
    * In entrambi i casi, l'esito viene archiviato in modo persistente in `evasion_log.json`, creando il Dataset necessario per la futura implementazione del modello AI reale.

---
*Progetto accademico in fase di Proof of Concept. Per scopi puramente educativi e di ricerca.*
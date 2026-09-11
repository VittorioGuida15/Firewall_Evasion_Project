# 🛡️ AI-Driven Firewall Evasion System

**AI-Driven Firewall Evasion System** è un Proof of Concept (PoC) accademico sviluppato per dimostrare come l'Intelligenza Artificiale (LLM) possa essere utilizzata per automatizzare le tecniche di elusione dei controlli di rete.

Il sistema si interfaccia **con le API di Google Gemini** per generare strategie di evasione dinamiche basate sull'apprendimento iterativo (Trial & Error). Inoltre, il progetto implementa un'architettura a interfacce intercambiabili che include un motore "Mock" per simulare l'IA, permettendo di testare il ciclo di orchestrazione in ambienti offline o di debug.

---

## 🧩 Funzionalità principali
*   **Orchestratore Autonomo:** Un Evasion Loop che invia automaticamente pacchetti anomali e analizza la reazione del bersaglio.
*   **Intelligenza Artificiale Reale (`llm_engine.py`):** Integrazione diretta con i modelli Gemini per analizzare il traffico di baseline, leggere i log dei fallimenti e dedurre mutazioni logiche mirate.
*   **Motore Mock Intercambiabile (`llm_engine_mock.py`):** Un simulatore LLM per testare l'infrastruttura offline.
*   **Motore di Mutazione (`mutation_engine.py`):** Modifica dinamica dei pacchetti raw tramite Scapy (manipolazione TCP Flags, IP TTL, Window Size, Source Port).
*   **Analisi del Traffico (`traffic_analyzer.py`):** Generazione dinamica di una baseline di rete per istruire l'IA su come "mimetizzare" l'attacco.
*   **Resilienza e Sicurezza:** Gestione avanzata delle allucinazioni dell'IA (parsing JSON rigoroso) e rate limiting strutturato per non sovraccaricare il server bersaglio o l'API.
*   **Ambiente Dockerizzato:** Containerizzazione completa di Attaccante e Target (Nginx + Iptables) per test sicuri e isolati senza impattare la macchina host.

---

## 📁 Struttura del progetto
```text
Firewall_Evasion_Project/
├── .vscode/                    → Impostazioni dell'editor di sviluppo
├── docker/                     → Configurazione degli ambienti isolati
│   ├── attacker/               
│   │   └── Dockerfile.attacker → Immagine per l'esecuzione degli script (permessi NET_ADMIN)
│   └── target/                 
│       ├── Dockerfile.target   → Immagine server web Nginx
│       └── setup_defense.sh    → Script di configurazione delle regole Iptables (Firewall)
│
├── src/                        → Core Logic dell'Attaccante
│   ├── evasion_loop.py         → L'orchestratore principale (loop di test e mutazioni)
│   ├── llm_engine.py           → Motore AI Reale (Integrazione API Gemini)
│   ├── llm_engine_mock.py      → Motore AI Simulato (Fallback per test offline)
│   ├── mutation_engine.py      → Libreria di funzioni Scapy per mutare i pacchetti
│   ├── successFeedbackAnalyzer.py → Logica di valutazione delle risposte di rete
│   └── traffic_analyzer.py     → Sniffer passivo per generare la baseline di rete
│
├── tests/                      → Suite di test e script di utility
│   ├── model_list.txt          → Elenco dei modelli Gemini disponibili
│   ├── model_list_generator.py → Utility per interrogare le API sui modelli attivi
│   ├── prova.py                → Script di test generico
│   ├── test_SuccessFeedbackAnalyzer.py
│   ├── test_llm.py             
│   ├── test_llm_engine.py      
│   ├── test_mutations.py       
│   └── test_scapy.py           
│
├── .gitignore                  → File e cartelle ignorate da Git
├── .env.example                → Template per le variabili d'ambiente necessarie
├── Project_draft_9.1.pdf       → Documentazione accademica del progetto
├── README.md                   → Documentazione del repository (questo file)
├── baseline_example.json       → Template del traffico normale (Quick Start)
├── docker-compose.yml          → Configurazione per avviare l'infrastruttura
├── evasion_log_example.json    → Esempio di struttura del log
└── requirements.txt            → Dipendenze Python (scapy, google-genai, python-dotenv)
```

---

## 🛠️ Requisiti
*   **Docker Desktop** (o Docker Engine + Docker Compose)
*   **Python 3.10+**
*   **API Key di Google Gemini:** Necessaria per utilizzare il vero LLM tramite `llm_engine.py`. Puoi ottenerne una gratuitamente registrandoti su [Google AI Studio](https://aistudio.google.com/).

---

## ⚙️ Setup del progetto

1. **Clona il repository:**
   ```bash
   git clone https://github.com/VittorioGuida15/Firewall_Evasion_Project.git
   cd Firewall_Evasion_Project
   ```

2. **Configura le variabili e i file generati:**
   Usa i file di esempio forniti nel repository per creare la tua configurazione locale:
   ```bash
   # 1. Copia il template per le chiavi API
   cp .env.example .env
   
   # 2. Inserisci la tua chiave dentro il nuovo file .env
   # GEMINI_API_KEY=la_tua_chiave_api_qui
   
   # 3. Crea una Baseline di partenza fittizia per far partire subito l'AI
   cp baseline_example.json baseline.json
   ```
   *(Nota: Il file `evasion_log.json` non necessita di essere copiato, l'orchestratore lo creerà automaticamente da zero al primo avvio).*

3. **Costruisci i container Docker:**
   ```bash
   docker-compose build
   ```

---

## 🚀 Avvio del progetto

Il progetto prevede l'uso di due container in esecuzione simultanea sulla stessa rete Docker isolata.

### 💻 1. Avvio dell'Infrastruttura (Target)
Avvia i container in background. Il `target_server` eseguirà lo script `setup_defense.sh` configurando le regole del firewall.
```bash
docker-compose up -d
```

### 💻 2. Accesso al Container Attaccante
Per manipolare il traffico raw di rete con Scapy, è necessario operare all'interno del container attaccante (che gode dei privilegi `NET_ADMIN`).
```bash
docker exec -it attacker_client bash
```

### 🧪 3. Esecuzione del Test di Evasione (PoC)
All'interno del container `attacker_client`, lancia l'orchestratore. Il programma dialogherà autonomamente con l'LLM per trovare il bypass al firewall:
```bash
python src/evasion_loop.py
```
*I risultati, i log generati in tempo reale e il ragionamento strategico dell'IA verranno stampati a schermo.*

---

## 🧠 Flusso di esecuzione (Architettura)

0. **Fase 0 (Profilazione del Traffico):** Prima di un attacco, l'IA ha bisogno di conoscere le abitudini della rete per potersi mimetizzare. Nel setup abbiamo copiato una `baseline.json` già pronta. Tuttavia, per un test 100% realistico, puoi avviare lo sniffer `src/traffic_analyzer.py` e, in un altro terminale, generare traffico legittimo verso il server (ad esempio inviando il comando `curl http://target_server` ripetutamente) per creare una Baseline dinamica dal vivo.
1. **Fase Iniziale (Paziente Zero):** L'orchestratore genera un pacchetto raw palesemente anomalo (es. TCP XMAS) e lo invia al `target_server`.
2. **Valutazione del Firewall:** Iptables sul server bersaglio analizza il pacchetto, lo scarta in modo silente (DROP) e l'orchestratore registra il fallimento.
3. **Analisi Logica (AI Agent):** L'orchestratore interroga `llm_engine.py` (o il Mock). L'IA incrocia i dati della *Baseline* con la cronologia dei fallimenti passati (`evasion_log.json`), deducendo la mutazione più logica da applicare. L'output è un JSON rigoroso contenente il "ragionamento" e le istruzioni di attacco.
4. **Applicazione della Mutazione:** Il `mutation_engine.py` fornisce  le funzioni per alterare la struttura del pacchetto in memoria e re-inviarlo al bersaglio.
5. **Feedback Loop:**
    * Se il pacchetto elude il firewall (Score +1), il ciclo si interrompe segnalando il successo.
    * Se fallisce (Score -1), il log viene aggiornato e l'IA ritenta con una nuova strategia, auto-correggendosi per un massimo di N iterazioni.

from scapy.all import IP, TCP, sr1 

def evaluate_response(response):
    """Valuta la risposta del firewall/server e restituisce un punteggio."""
    if response is None:
        print("Esito: Nessuna risposta (probabilmente scartato - DROP). Score: -1")
        return -1
    elif response.haslayer(TCP):
        if response[TCP].flags == "SA": #SYN-ACK
            print("Esito: Risposta SYN-ACK (Connessione accettata). Score: +1")
            return 1
    elif response[TCP].flags in  ["R", "RA"]: #RST
        print("Esito: Connessione rifiutata attivamente (RST). Score: -1")
        return -1
    return -1


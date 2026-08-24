from scapy.all import IP, TCP, sr1

ip_layer = IP(dst="target_server")
tcp_layer = TCP(dport=80, flags="S") #SYN per testare se la porta è aperta
packet = ip_layer / tcp_layer

print("Invio pacchetto e attesa riposta (3 sec)")
response = sr1(packet, timeout=3, verbose=0)

print("Risultato Success Fedback Analyzer")
if response is None:
    print("FALLIMENTO: il pacchetto è stato bloccato!")
elif response.haslayer(TCP):
    if response[TCP].flags == "SA": #SYN-ACK
        print("SUCCESSO: il server ha risposto con SYN-ACK")
    elif response[TCP].flags == "R" or response[TCP].flags == "RA": #RST
        print("FALLIMENTO: Il firewall ha rifiutato la connessione bloccandola attivamente (RST).")
else:
    print("ATTENZIONE: Ricevuta una risposta anomala.")
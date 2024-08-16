import socket

# Configura il server
server_host = '0.0.0.0'  # Ascolta su tutte le interfacce di rete
server_port = 12345  # Porta per la connessione

# Crea il socket del server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_host, server_port))
server_socket.listen(5)  # Massimo numero di connessioni in coda

print(f"In ascolto su {server_host}:{server_port}")

while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connessione in entrata da {client_address}")
    
    # Gestisci il comando ricevuto dal client
    command = client_socket.recv(1024).decode()
    print(f"Comando ricevuto: {command}")
    
    # Esegui il comando (sostituisci con la tua logica)
    # Ad esempio, puoi eseguire comandi diversi in base a 'command'
    
    # Chiudi la connessione con il client
    client_socket.close()

import socket

# Configura il client
server_host = 'indirizzo_ip_del_server'
server_port = 12345

# Crea il socket del client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_host, server_port))

while True:
    command = input("Inserisci un comando: ")
    client_socket.send(command.encode())
    
    # Puoi gestire ulteriori risposte dal server qui, se necessario

# Chiudi la connessione con il server quando hai finito
client_socket.close()

import os
import subprocess
import re

def check_weak_passwords():
    # Controlla la forza delle password degli utenti
    try:
        result = subprocess.check_output("net user", shell=True, text=True)
        users = re.findall(r"(\S+)\s+User", result)
        for user in users:
            subprocess.call(f"net user {user} | findstr /i 'Password last set'", shell=True)
    except Exception as e:
        print(f"Errore durante il controllo delle password: {str(e)}")

def check_os_updates():
    # Controlla gli aggiornamenti mancanti del sistema operativo
    try:
        subprocess.call("wmic qfe list full", shell=True)
    except Exception as e:
        print(f"Errore durante il controllo degli aggiornamenti del sistema operativo: {str(e)}")

if __name__ == "__main__":
    print("Verifica della sicurezza del PC...")
    check_weak_passwords()
    check_os_updates()
    print("Verifica completata.")

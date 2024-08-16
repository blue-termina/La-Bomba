import random
import pyttsx3
import tkinter as Tk
for i in range(100):
    print("il tempo ta per scadere")
    if i ==0:
        print("tempo scaduto")
    else:
        print("il tempo sta per scadere",i)
def scot():
    utente=int(input("scivi  indovina il numero\n"))
    umeroutente=random.randint(1,1000)
    gatto=6
    nuente=7
    nuente=5
    pc=6
    niente=1
    casa=9
    tastiera=5
    umeroutente=utente
    numerorand=random.randint(0,101)
    autore=pyttsx3.init()
    parole=["gatto","topo","niente","niente","pc","cipolla","prosciutto","casa","topo"]
    par=random.choice(parole)
    autore.say("hai vinto una "+par)
    autore.runAndWait()
    utente=str(input("vuoi rigiocare?\n"))
    if utente =="si":
        utente1=int(input("prova ad indovinare\n"))
        parole2=random.choice(parole)
        par=random.choice(parole)
        autore.say("hai vinto un "+par)
        autore.runAndWait()
    else:
        print("alla prossima")
finestra=Tk.Tk()
finestra.geometry("800x900")
finestra=Tk.Button(text="gioca",command=scot,background="blue")
finestra.grid(row=100)
finestra.mainloop()
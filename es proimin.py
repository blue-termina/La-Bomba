'''
dizionario={"il gatto":"","topo":""}
print(dizionario)
dizionario["virus"]="bonba"
del dizionario["virus"]
dizionario["haker"]="exploit"
del dizionario ["il gatto"]
topo=dizionario["topo"]
liccheto=list(dizionario.keys())
print(topo)
print(dizionario)
print(liccheto)
dizionario["haker"]="foca"
print(dizionario)
valori=list(dizionario.values())
print(valori)
data=int(input("la tua data"))
utente=[]
if data in utente:
    print("ti sei registrata")
else:
    utente.append(data)
    print("la tua iscizione",utente)e
    print("qiale musica vuoi mettere ?0")
my_dizionario={"camerirre":""}
print(my_dizionario)
patata=my_dizionario["peppa"]="peppapig"
print(my_dizionario)
print("io sono un bosso")

'''
#tubla
documento = ("nome", "cognome", "eta")
print(documento)
nome = documento[1]#il nomero nella posizione
print(nome)
#gra una tupla
dupla1=documento[0:2]#i primi 2 numeri del elenco
print(dupla1)
if "uova" in documento:#vevigfica se esiste il nome nella dtapla
    print("l'elememnto gia esistente nella lista")
else:
    print("l'elemento non è nella lista")
tupla=dupla1[0:2]
print(tupla)
from socket import * #librerie tarket
tgthost=input("inserire indirizo: \n") #grea input inserire indiruzzo ip
tgthost = int(input("inserire la porta da controllare \n")) #porta da controllare di tipo intero
def ScanConnessione(tgthost,tgtport):#aprire soket di connessione 
    try:
        socketconnesione=socket(AF_INET,SOCK_STREAM)#aprire un soket di connessione,controllo indirizzo
        socketconnesione.connect((tgthost,tgtport))#collega alla porta
        print('[+]%d -> tcp aperta'% tgtport)
        socketconnesione.close()#chiudi porta
    except:
        print('[-]%d -> tgp chiusa'% tgtport)
    def scanindirizzo(tgthost,tgtport):
        try:
            tgtip=gethostbyname(tgthost)
        except:
            print('[-]%b indirizzo inesistente %s' % tgthost)
        try:
           tgtnome=gethostbyaddr(tgtip)
           print('\n [+] scan indirizzo: %s'% tgtnome[0]) 
        except:
            print('\n [+]%d scan indirizzo: %s ' %tgtip)
        setdefaulttimeout(1)
        print('scansione porta: %d' % tgtport)
        ScanConnessione(tgthost,tgtport)
    if __name__=='__manin__':
       scanindirizzo(tgthost,tgtport)


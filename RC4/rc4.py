#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
import sys
import getopt
import time
import os

"""
    ESTE CODIGO FUE GENERADO EN BASE AL CODIGO:
    Copyright (C) 2012 Bo Zhu http://about.bozhu.me
    PARA LA MATERIA: ESPECIALIZACION EN SEGURIDAD INFORMATICA
    UNIVERSIDAD AUTONOMA DE OCCIDENTE
    AUTORES:
    HENRY SARRIA
    FRANCISCO RIASCOS
"""

#==================================================
#Definicion de la funcion KSA
def KSA(key):
    keylength = len(key)

    S = range(256)

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # intercambio

    return S

#==================================================
#Definicion de la funcion PRGA
def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # intercambio

        K = S[(S[i] + S[j]) % 256]
        yield K

#==================================================
#Definicion de la funcion RC4
def RC4(key):
    S = KSA(key)
    return PRGA(S)

#==================================================
#Definicion de la funcion para convertir string a decimal
def convert_char_to_dec(s):
    #print (ord(c) for c in s)
    return [ord(c) for c in s]

#==================================================
#Definicion de la operacion RC4
def operation_rc4(message_file, key_file, finalfile):
    #Se inicializan variables
    key=""
    keystream=""
    file_route = route + "/" + finalfile

    key = convert_char_to_dec(key_file)
    keystream = RC4(key)

    #se realiza la operacion XOR entre el keystream y el mensaje
    code = [ (ord(x) ^ next(keystream)) for x in message_file ]    

    codechar = [chr(x) for x in code]       #se convierte el mensaje de entero a char
    fullStr = ''.join(codechar)             #se convierte el array en un string
    file = open(file_route, "w")            #se lee la ruta donde se alamacenara el criptograma 
    file.write(fullStr)                     #se escribe el mensaje en el archivo
    print (file)
    file.close()

#==================================================
#Definicion de la funcion de Documentacion
def Docs(flags):
    #print(flags)

    _authors = """
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Riascos          francisco.riascos@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autonoma de Occidente
    Especializacion en Seguridad Infromatica
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II
"""
    _title_ = 'ALGORITMO RIVEST CIPHER 4 (RC4)'
    if (len(flags)==0 or (flags[0] in ('-h'))):        
        __doc__ = """
            """+_title_+"""
    Sintaxis: python """+sys.argv[0]+""" <operacion>
    <operacion>:
        enc:    Cifrar utilizando el algoritmo RC4
        dec:    Descifrar algo cifrado con el algortimo RC4"""+_authors

    elif ((len(flags)<=2) and (flags[0]=='enc')):
        _title_ = 'CIFRADO CON RC4'
        __doc__ = """
                """+_title_+"""
    Sintaxis: python """+sys.argv[0]+""" enc -m <mensaje> -k <clave> -o <archivofinal>
    <mensaje>:      Nombre del archivo con el texto en plano.
    <clave>:        Nombre del archivo con la llave o clave con la que se desea cifrar el texto.
    <archivofinal>  Nombre del archivo en donde se almacenara el criptograma (no colocar extension)
    Nota:   Todos los archivos deben estar en la misma carpeta donde se encuentre el script.
    Ejemplo:    python """+sys.argv[0]+""" enc -m message.txt -k key.txt -o finalfile"""+_authors

    elif (((len(flags)<=2) and (flags[0]=='dec')) or ((len(flags)<=2))):
        _title_ = 'DESCIFRADO DE RC4'
        __doc__ = """
                """+_title_+"""
    Sintaxis: python """+sys.argv[0]+""" dec -m <criptograma> -k <clave> -o <archivofinal>
    <criptograma>:  Nombre del archivo con el texto cifrado.
    <clave>:        Nombre del archivo con la llave o clave con la que se desea descifrar el texto cifrado.
    <archivofinal>  Nombre del archivo en donde se almacenara el mensaje descifrado (no colocar extension)
    Nota:   Todos los archivos deben estar en la misma carpeta donde se encuentre el script.
    Ejemplo:   python """+sys.argv[0]+""" enc -c cripto.txt -k key.txt -o finalfile"""+_authors
    try:
        sys.exit (__doc__)
    except Exception:
        pass

#==================================================
#Definicion de la operacion Main
def main(argu):
    #inicializo variables
    start_time = time.time()
    global route 
    route = os.getcwd()     #ruta del archivo de python rc4.py
    flags = 'm:k:o:'        #banderas para los argumentos pasados en la CLI
    args = argu[1:]         #se asignan el resto de argumentos de la CLI

    try:
        opts,arg = getopt.getopt(args,flags)        #se comparan si los argumentos ingresados son conrrectos
    except getopt.GetoptError:
        print("Error en el comando ingresado, por favor revisar la ayuda del programa")
        sys.exit(2)

    for opt,arg in opts:
        if opt=='-m':
            message_route = route + "/" + arg       #se lee la ruta del archivo mensaje
            file = open(message_route,'r')          
            message_file = file.read()              #se lee el archivo mensaje
            file.close()
        if opt=='-k':
            key_route = route + "/" + arg           #se lee la ruta del archivo clave
            file = open(key_route,'r')              
            key_file = file.read()                  #se lee el archivo clave
            file.close()
        elif opt=='-o':
            finalfile = arg + ".txt"

    operation_rc4(message_file, key_file, finalfile)
    final_time = time.time()-start_time
    print("==========================================")
    print("OPERACION TERMINADA CON EXITO")
    print("Tiempo de Ejecucion: " + str(final_time) + "sg")
    print("==========================================")

#==================================================
#Funcion principal
if __name__ == '__main__':
    Docs(sys.argv[1:]);
    main(sys.argv[1:]);
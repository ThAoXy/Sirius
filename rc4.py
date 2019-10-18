#!/usr/bin/env python
#-*-coding: utf-8-*-
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
    FRANCISCO TORRES
"""

def KSA(key):
    keylength = len(key)

    S = range(256)

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # intercambio

    return S


def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # intercambio

        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key):
    S = KSA(key)
    return PRGA(S)

def convert_char_to_dec(s):
    #print (ord(c) for c in s)
    return [ord(c) for c in s]

def operation_rc4(_type, message_file, key_file, archivo):
    #Se inicializan variables
    if (_type == "enc"):
        print("PROCESO DE CIFRADO RC4")
        print("El mensaje a cifrar es: " + message_file)
        print("La clave que se utilizara para cifrar el mesnaje es: " + key_file)
    elif(_type == "dec"):
        print("PROCESO DE DESCIFRADO RC4")
        print("El criptograma a descifrar es: " + message_file)
        print("La clave que se utilizara para descifrar el mesnaje es: " + key_file)

    key=""
    keystream=""
    file_route = route + "/" + archivo + ".txt"

    key = convert_char_to_dec(key_file)
    keystream = RC4(key)

    print("El " + archivo + " en decimal es:")
    #se realiza la operacion XOR entre el keystream y el mensaje
    code = [ (ord(x) ^ next(keystream)) for x in message_file ]    
    print (code)

    print("El " + archivo + " en char es:")
    codechar = [chr(x) for x in code]       #se convierte el mensaje de entero a char
    print(codechar)
    fullStr = ''.join(codechar)             #se convierte el array en un string
    file = open(file_route, "w")            #se lee la ruta donde se alamacenara el criptograma 
    file.write(fullStr)                     #se escribe el mensaje en el archivo
    print (file)
    file.close()

def Docs(flags):
    #print(flags)

    _authors = """
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Torres           francisco.torres@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autónoma de Occidente
    Especialización en Seguridad Infromática
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

    elif (((len(flags)<=2) and (flags[0]=='enc')) or ((len(flags)<=2))):
        _title_ = 'CIFRADO CON RC4'
        __doc__ = """
                """+_title_+"""
    Sintaxis: python """+sys.argv[0]+""" enc -m <mensaje> -k <clave>
    <mensaje>:  Nombre del archivo con el texto en plano.
    <clave>:    Nombre del archivo con la llave o clave con la que se desea cifrar el texto.
    Ejemplo:    python """+sys.argv[0]+""" enc -m message.txt -k key.txt"""+_authors

    elif (((len(flags)<=2) and (flags[0]=='dec')) or ((len(flags)<=2))):
        _title_ = 'DESCIFRADO DE RC4'
        __doc__ = """
                """+_title_+"""
    Sintaxis: python """+sys.argv[0]+""" dec -m <criptograma> -k <clave>
    <criptograma>:  Nombre del archivo con el texto cifrado.
    <clave>:        Nombre del archivo con la llave o clave con la que se desea descifrar el texto cifrado.
    Ejemplo:    python """+sys.argv[0]+""" enc -c cripto.cif -k key.txt"""+_authors
    try:
        sys.exit (__doc__)
    except Exception:
        pass

def main(argu):
    #inicializo variables
    start_time = time.time()
    global route 
    route = os.getcwd()     #ruta del archivo de python rc4.py
    flags = 'm:k:'          #banderas para los argumentos pasados en la CLI
    global _type
    _type = ""              #tipo de operacion que se realizara

    _type = argu[0]         #se le asigna la operacion que se realizara
    args = argu[1:]         #se asignan el resto de argumentos de la CLI

    print(route)
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

    if _type == "enc":          
        #Si la operacion es cifrar
        archivo="criptograma"
 
    elif _type == 'dec':        
        #Si la operacion es descifrar
        archivo="mensaje"
 
    else:
        # Si se encuentran errores, se despliega la ayuda
        print("Error en la operacion, por favor revisar")
        Docs(argu)
        sys.exit(2)

    operation_rc4(_type, message_file, key_file, archivo)
    final_time = time.time()-start_time
    print("Tiempo de Ejecución: " + str(final_time) + "sg")

if __name__ == '__main__':
    Docs(sys.argv[1:]);
    main(sys.argv[1:]);
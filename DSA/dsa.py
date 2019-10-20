import sys
import getopt
import time
import os
from random import randrange
from hashlib import sha1
from gmpy2 import xmpz, to_binary, invert, powmod, is_prime

"""
    ESTE CODIGO FUE GENERADO EN BASE AL CODIGO:
    Copyright (C) pymq - https://github.com/pymq
    PARA LA MATERIA: ESPECIALIZACION EN SEGURIDAD INFORMATICA
    UNIVERSIDAD AUTONOMA DE OCCIDENTE
    AUTORES:
    HENRY SARRIA
    FRANCISCO RIASCOS
"""

#===============================================================================================================
#PROCESO DE GENERACION DE LLAVES

#funcion para generar los primos P,Q
def generate_p_q(L, N):     
    g = N  # g >= 160
    n = (L - 1) // g        #n es igual cociente entre 1023/160 = 6
    b = (L - 1) % g         #b es igual al residuo entre 1023/160 = 63
    while True:
        # generate q
        while True:
            s = xmpz(randrange(1, 2 ** (g)))        #randrange es una funcion que brinda un numero aleatorio entre 1 y 2^160
            a = sha1(to_binary(s)).hexdigest()      #se convierte s a binario y se le saca el hash en hexadecimal
            zz = xmpz((s + 1) % (2 ** g))           #se ubica un numero + 1 a s y se confirma que este en el cuerpo de 2^160
            z = sha1(to_binary(zz)).hexdigest()     #se convierte zz a binario y se le sacah el hash en hexadecimal
            U = int(a, 16) ^ int(z, 16)             #se covierte los hashes a enteros en base 16 y se realiza una operacion XOR
            mask = 2 ** (N - 1) + 1                 #se genera una mascara que sea un bit menos a 2^160 osea (2^159) + 1
            q = U | mask                            #se realiza una operacion OR entre U y la mascara
            if is_prime(q, 20):                     #se verifica si q es primo de 20
                break
        # generate p
        i = 0  # counter
        j = 2  # offset
        while i < 4096:
            V = []
            for k in range(n + 1):
                arg = xmpz((s + j + k) % (2 ** g))
                zzv = sha1(to_binary(arg)).hexdigest()
                V.append(int(zzv, 16))
            W = 0
            for qq in range(0, n):
                W += V[qq] * 2 ** (160 * qq)
            W += (V[n] % 2 ** b) * 2 ** (160 * n)
            X = W + 2 ** (L - 1)
            c = X % (2 * q)
            p = X - c + 1  # p = X - (c - 1)
            if p >= 2 ** (L - 1):
                if is_prime(p, 10):
                    return p, q
            i += 1
            j += n + 1

#funcion apara calcular G en nuestro diagrama
def generate_g(p, q):                   
    while True:
        h = randrange(2, p - 1)         #esto es H en nuestro diagrama osea el numero aleatorio que deberia ser 2
        exp = xmpz((p - 1) // q)        #esto es simplemente el cociente de 1024/160 = 6 que en nuestro diagrama es (P-1)/Q  
        #exp = ((p - 1) // q)        #esto es simplemente el cociente de 1024/160 = 6 que en nuestro diagrama es (P-1)/Q      
        g = powmod(h, exp, p)           #aqui se calcula G osea esto es simplemente (H^6) mod 1024 
        if g > 1:
            break
    return g                            

#funciona para calcular la llave privada (X) y Y en nuestro diagrama
def generate_keys(g, p, q):             
    x = randrange(2, q)  # x < q        #genera un numero aleatorio entre 2 y 160, esto es la llave privada
    y = powmod(g, x, p)                 #realiza y = (g^x) mod P
    return x, y                         #regresa X,Y (llave privada,Y)


def generate_params(L, N):              
    p, q = generate_p_q(L, N)           #se generan los primos P,Q
    g = generate_g(p, q)                #se genera G (motor aleatoridad)
    return p, q, g                      #devuelve P,Q,G en nuestro digrama

#=============================================================================================================
#PROCESO DE FIRMADO

def sign(M, p, q, g, x):
    if not validate_params(p, q, g):            #se validan parametros
        raise Exception("Invalid params")
    while True:
        k = randrange(2, q)  # k < q            #se genera un numero aleatorio entre 2 y Q esto es el KE en nuestro diagrama
        r = powmod(g, k, p) % q                 #se calcula R = G^(KE mod P) mod Q
        m = int(sha1(M).hexdigest(), 16)        #se saca el hash del mensaje y se pone en decimal base 16
        print("El Hash del mensaje es:")
        print(m)
        try:
            s = (invert(k, q) * (m + x * r)) % q    #se calcula S = KE^-1(hash(M)+X*R)
            return r, s                         #se devulve la firma que es R,S
        except ZeroDivisionError:
            pass

#=============================================================================================================
#PROCESO DE VERIFICACION DE FIRMA

def verify(M, r, s, p, q, g, y):
    if not validate_params(p, q, g):            #se validan parametros P,Q,G
        raise Exception("Invalid params")
    if not validate_sign(r, s, q):              #se validan parametros R,S
        return False
    try:
        w = invert(s, q)                        #se calcula w = S^-1 mod q
    except ZeroDivisionError:
        return False
    m = int(sha1(M).hexdigest(), 16)            #se saca el hash del mensaje y se pone en decimal base 16
    print("El Hash del mensaje es:")
    print(m)
    u1 = (m * w) % q                            #se calcula U1 = (hash(m)*S^-1) mod Q
    u2 = (r * w) % q                            #se calcula U2 = (R*S^-1) mod Q
    # v = ((g ** u1 * y ** u2) % p) % q
    v = (powmod(g, u1, p) * powmod(y, u2, p)) % p % q       #se calcula V = (G^U1 mod P)*(Y^U2 mod P) mod P mod Q
    print("El valor de V es:")
    print(v)
    if v == r:                                  #si V == R entonces la firma es valida
        return True
    return False

#funcion para validar parametros P,Q,G
def validate_params(p, q, g):
    if is_prime(p) and is_prime(q):                         #se valida si P es numero primo 'Y' si Q es un numero primo
        return True
    if powmod(g, q, p) == 1 and g > 1 and (p - 1) % q:      #confirma si G^Q mod P = 1 'Y' G>1 'Y' (P-1) mod Q = 1
        return True
    return False

#funcion para validar parametros de firma R,S
def validate_sign(r, s, q):
    if r < 0 and r > q:         #se valida que R>0 'Y' que R<Q
        return False
    if s < 0 and s > q:         #se valida que S>0 'Y' que S<Q
        return False
    return True

#=============================================================================================================
#Funcion de Documentacion y Help
def Docs(flags):
    _authors = """
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Riascos          francisco.riascos@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autónoma de Occidente
    Especialización en Seguridad Infromática
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II
"""
    _title_ = 'DIGITAL SIGNATURE ALGORITHM (DSA)'
    if (len(flags)==0 or (flags[0] in ('-h'))):        
        __doc__ = """
            """+_title_+"""
    Sintaxis: python3 """+sys.argv[0]+""" <operacion>
    <operacion>:
        gen:    Proceso de generacion de llaves.
        sig:    Proceso de firmado de hash.
        ver:    Proceso de verificacion de firma."""+_authors

    elif ((len(flags)<=2) and (flags[0]=='gen')):
        _title_ = 'GENERACION DE LLAVES CON DSA'
        __doc__ = """
                """+_title_+"""
    Sintaxis: python3 """+sys.argv[0]+""" gen -p <llavepublica> -k <llaveprivada>
    <llavepublica>    Nombre del archivo en donde se almacenaran los parametros [p,q,g,y] (no colocar extension)
    <llaveprivada>    Nombre del archivo en donde se almacenara el parametro [x] (no colocar extension)
    Ejemplo:    python3 """+sys.argv[0]+""" gen -p llavepublica -k llaveprivada"""+_authors

    elif ((len(flags)<=2) and (flags[0]=='sig')):
        _title_ = 'FIRMADO DE HASH CON DSA'
        __doc__ = """
                """+_title_+"""
    Sintaxis: python3 """+sys.argv[0]+""" sig -p <llavepublica> -k <llaveprivada> -m <archivo> -s <firma>
    <llavepublica>    Nombre del archivo en donde estan almancenados los parametros [p,q,g,y] 
    <llaveprivada>    Nombre del archivo en donde esta almancenado el parametro [x]
    <archivo>:        Nombre del archivo con el mensaje a firmar.
    <firma>           Nombre del archivo en donde se almacenara la firma (no colocar extension)
    Ejemplo:    python3 """+sys.argv[0]+""" sig -p llavepublica.txt -k llaveprivada.txt -m mensaje.txt -s firma"""+_authors
    
    elif ((len(flags)<=2) and (flags[0]=='ver')):
        _title_ = 'VERIFICACION DE FIRMA'
        __doc__ = """
                """+_title_+"""
    Sintaxis: python3 """+sys.argv[0]+""" ver -p <llavepublica> -m <mensaje> -s <firma>
    <llavepublica>    Nombre del archivo en donde estan almancenados los parametros [p,q,g,y]
    <archivo>:        Nombre del archivo con el mensaje a firmar.
    <firma>           Nombre del archivo en donde esta almacenada la firma.
    Ejemplo:    python """+sys.argv[0]+""" ver -p llavepublica.txt -m mensaje.txt -s firma.txt"""+_authors
    try:
        sys.exit (__doc__)
    except Exception:
        pass
#=============================================================================================================
#PROCESO MAIN

def main(argu):
#def main():
    #inicializo variables
    start_time = time.time()
    global route
    route = os.getcwd()     #ruta del archivo de python dsa.py
    _type = ""              #tipo de operacion que se realizara
    N = 160
    L = 1024

    _type = argu[0]         #se le asigna la operacion que se realizara
    args = argu[1:]         #se asignan el resto de argumentos de la CLI

    if (_type == 'gen'):
        flags = 'p:k:'      #banderas para los argumentos pasados en la CLI
    elif (_type == 'sig'):
        flags = 'p:k:m:s:'  #banderas para los argumentos pasados en la CLI
    elif (_type == 'ver'):
        flags = 'p:m:s:'    #banderas para los argumentos pasados en la CLI

    try:
        opts,arg = getopt.getopt(args,flags)        #se comparan si los argumentos ingresados son conrrectos
    except getopt.GetoptError:
        print("Error en el comando ingresado, por favor revisar la ayuda del programa")
        sys.exit(2)

    for opt,arg in opts:
        if opt=='-p':
            if _type == 'gen':
                public_file = arg + ".txt"
                public_route = route + "/" + public_file
            else:
                public_route = route + "/" + arg            #se lee la ruta del archivo llave publica
                file = open(public_route,'r')          
                public_file = file.read()                   #se lee el archivo llave publica
                file.close()
        elif opt=='-k':
            if _type == 'gen':
                private_file= arg + ".txt"
                private_route = route + "/" + private_file
            else:
                private_route = route + "/" + arg           #se lee la ruta del archivo llave privada
                file = open(private_route,'r')          
                private_file = file.read()                  #se lee el archivo llave privada
                file.close()
        elif opt=='-m':
            message_route = route + "/" + arg               #se lee la ruta del archivo hash del mensaje
            file = open(message_route,'r', encoding = "ISO-8859-1")          
            message_file = file.read()                      #se lee el archivo hash del mensaje
            file.close()
        elif opt=='-s':
            if _type == 'sig':
                signature_file = arg + ".txt"  
                signature_route = route + "/" + signature_file
            else:
                signature_route = route + "/" + arg         #se lee la ruta del archivo firma
                file = open(signature_route,'r')          
                signature_file = file.read()                #se lee el archivo firma
                file.close()

    if (_type == 'gen'):
        #PROCESO DE GENERACION DE LLAVES
        p, q, g = generate_params(L, N)                     #donde P,Q (son los primos), G (es motor aleatoridad)
        x, y = generate_keys(g, p, q)                       #donde X (es la llave privada), Y
        
        print("La llave publica es: ")
        print([p,q,g,y])
        print("Donde:")
        print("El numero primo P es:")
        print(p)
        print("El numero primo Q es:")
        print(q)
        print("El numero G es:")
        print(g)
        print("El numero Y es:")
        print(y)
        print("La llave Privada es:")
        print(x)
        pstr = str(p)
        qstr = str(q)
        gstr = str(g)
        ystr = str(y)
        publickey = [pstr,qstr,gstr,ystr]
        publickeystr = ','.join(publickey)

        file = open(public_file, "w")                       #se lee la ruta donde se alamacenara la llave publica
        file.write(publickeystr)                            #se escribe el mensaje en el archivo llave publica
        print (file)
        file.close()

        fullStr = str(x)                                    #se convierte el array en un string
        file = open(private_file, "w")                      #se lee la ruta donde se alamacenara la llave privada 
        file.write(fullStr)                                 #se escribe el mensaje en el archivo llave privada
        print (file)
        file.close()
    elif (_type == 'sig'):
        #PROCESO DE FIRMADO DE HASH

        x = int(private_file)
        print("La llave privada es:")
        print(x)
        print("La llave publica es:")
        publickey = list(public_file.split(","))
        print(publickey)
        print("Donde:")
        pstr = publickey[0]
        p = int(pstr)
        print("El numero primo P es:")
        print(p)
        qstr = publickey[1]
        q = int(qstr)
        print("El numero primo Q es:")
        print(q)
        gstr = publickey[2]
        g = int(gstr)
        print("El numero primo G es:")
        print(g)
        ystr = publickey[3]
        y = int(ystr)
        print("El numero primo Y es:")
        print(y)

        M = str.encode(message_file, "ISO-8859-1")
        #print(M)
        r, s = sign(M, p, q, g, x)
        print("La firma es: ")
        print([r, s])
        print("Donde:")
        print("El numero R es:")
        print(r)
        print("El numero S es:")
        print(s)

        rstr = str(r)
        sstr = str(s)
        signature = [rstr,sstr]
        signstr = ','.join(signature)

        file = open(signature_file, "w")                       #se lee la ruta donde se alamacenara la firma 
        file.write(signstr)                                    #se escribe el mensaje en el archivo firma
        print (file)
        file.close()
    elif (_type == 'ver'):
        #PROCESO DE VERIFICACION DE FIRMA

        M = str.encode(message_file, "ISO-8859-1")

        print("La llave publica es:")
        publickey = list(public_file.split(","))
        print(publickey)
        print("Donde:")
        pstr = publickey[0]
        p = int(pstr)
        print("El numero primo P es:")
        print(p)
        qstr = publickey[1]
        q = int(qstr)
        print("El numero primo Q es:")
        print(q)
        gstr = publickey[2]
        g = int(gstr)
        print("El numero primo G es:")
        print(g)
        ystr = publickey[3]
        y = int(ystr)
        print("El numero primo Y es:")
        print(y)

        print("La firma es:")
        signature = list(signature_file.split(","))
        print(signature)
        print("Donde:")
        rstr = signature[0]
        r = int(rstr)
        print("El numero R es:")
        print(r)
        sstr = signature[1]
        s = int(sstr)
        print("El numero S es:")
        print(s)

        if verify(M, r, s, p, q, g, y):
            print("La firma es valida")
        else:
            print("La firma no es valida")

    final_time = time.time()-start_time
    print("==========================================")
    print("OPERACION TERMINADA CON EXITO")
    print("Tiempo de Ejecución: " + str(final_time) + "sg")
    print("==========================================")

if __name__ == "__main__":
    Docs(sys.argv[1:]);
    main(sys.argv[1:]);
#    main()
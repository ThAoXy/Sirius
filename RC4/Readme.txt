==========================================================================================
ALGORITMO RIVEST CIPHER 4 (RC4)

El siguiente es un script que contiene el funcionamiento del algortimo de cifrado RC4
El script contiene dos operaciones basicas las cuales son cifrar 'enc' y descifrar 'dec'.
El resultado final es almacenado en un archivo el cual el usuario debe definir el nombre.
Para obtener mas detalles del funcionamiento seguir leyendo la ayuda de abajo.
==========================================================================================
ALGORITMO RIVEST CIPHER 4 (RC4)
    Sintaxis: python rc4.py <operacion>
    <operacion>:
        enc:    Cifrar utilizando el algoritmo RC4
        dec:    Descifrar algo cifrado con el algortimo RC4
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Torres           francisco.torres@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autónoma de Occidente
    Especialización en Seguridad Infromática
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II

==========================================================================================
CIFRADO CON RC4
    Sintaxis: python rc4.py enc -m <mensaje> -k <clave>
    <mensaje>:  Nombre del archivo con el texto en plano.
    <clave>:    Nombre del archivo con la llave o clave con la que se desea cifrar el texto.
    Ejemplo:    python rc4.py enc -m message.txt -k key.txt
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Torres           francisco.torres@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autónoma de Occidente
    Especialización en Seguridad Infromática
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II

==========================================================================================
DESCIFRADO DE RC4
    Sintaxis: python rc4.py dec -m <criptograma> -k <clave>
    <criptograma>:  Nombre del archivo con el texto cifrado.
    <clave>:        Nombre del archivo con la llave o clave con la que se desea descifrar el texto cifrado.
    Ejemplo:    python rc4.py enc -c cripto.cif -k key.txt
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Torres           francisco.torres@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autónoma de Occidente
    Especialización en Seguridad Infromática
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II
==========================================================================================

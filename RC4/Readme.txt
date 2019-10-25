===========================================================================================================
ALGORITMO RIVEST CIPHER 4 (RC4)

El siguiente es un script que contiene el funcionamiento del algortimo de cifrado RC4.
El script contiene dos operaciones basicas las cuales son cifrar 'enc' y descifrar 'dec'.
Todos los archivo deben estar en la misma carpeta en donde se encuentre el script.
El resultado final es almacenado en un archivo el cual el usuario debe definir el nombre.
Para obtener mas detalles del funcionamiento seguir leyendo la ayuda de abajo.
===========================================================================================================
ALGORITMO RIVEST CIPHER 4 (RC4)
    Sintaxis: python rc4.py <operacion>
    <operacion>:
        enc:    Cifrar utilizando el algoritmo RC4
        dec:    Descifrar algo cifrado con el algortimo RC4
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Riascos          francisco.riascos@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autonoma de Occidente
    Especializacion en Seguridad Infromatica
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II
===========================================================================================================
CIFRADO CON RC4
    Sintaxis: python rc4.py enc -m <mensaje> -k <clave> -o <archivofinal>
    <mensaje>:      Nombre del archivo con el texto en plano.
    <clave>:        Nombre del archivo con la llave o clave con la que se desea cifrar el texto.
    <archivofinal>  Nombre del archivo en donde se almacenara el criptograma (no colocar extension)
    Nota:   Todos los archivos deben estar en la misma carpeta donde se encuentre el script.
    Ejemplo:    python rc4.py enc -m message.txt -k key.txt -o finalfile
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Riascos          francisco.riascos@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autonoma de Occidente
    Especializacion en Seguridad Infromatica
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II
===========================================================================================================
DESCIFRADO DE RC4
    Sintaxis: python rc4.py dec -m <criptograma> -k <clave> -o <archivofinal>
    <criptograma>:  Nombre del archivo con el texto cifrado.
    <clave>:        Nombre del archivo con la llave o clave con la que se desea descifrar el texto cifrado.
    <archivofinal>  Nombre del archivo en donde se almacenara el mensaje descifrado (no colocar extension)
    Nota:   Todos los archivos deben estar en la misma carpeta donde se encuentre el script.
    Ejemplo:   python rc4.py enc -c cripto.txt -k key.txt -o finalfile
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Riascos          francisco.riascos@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autonoma de Occidente
    Especializacion en Seguridad Infromatica
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II
===========================================================================================================

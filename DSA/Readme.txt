================================================================================================================
Digital Signature Algorithm

El siguiente es un script que realiza la generacion de un par de llaves
publica y privada, firma de un hash de un archivo y verificacion de la firma.
El script esta diseñado para generar archivos en formato .txt y alamacenarlos en la ruta donde se ejecuta el script.
El archivo mensaje y todos los demas archivos deben estar en la carpeta en donde se encuentre el script.
El script utiliza realiza un hash del mensaje bajo el algoritmo SHA1.
Por favor ver el archivo Requirements.txt y ver la ayuda del script.
================================================================================================================
GENERACION DE LLAVES CON DSA
    Sintaxis: python3 dsa.py gen -p <llavepublica> -k <llaveprivada>
    <llavepublica>    Nombre del archivo en donde se almacenaran los parametros [p,q,g,y] (no colocar extension)
    <llaveprivada>    Nombre del archivo en donde se almacenara el parametro [x] (no colocar extension)
    Ejemplo:    python3 dsa.py gen -p llavepublica -k llaveprivada
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Riascos          francisco.riascos@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autónoma de Occidente
    Especialización en Seguridad Infromática
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II
================================================================================================================
FIRMADO DE HASH CON DSA
    Sintaxis: python3 dsa.py sig -p <llavepublica> -k <llaveprivada> -m <archivo> -s <firma>
    <llavepublica>    Nombre del archivo en donde estan almancenados los parametros [p,q,g,y] 
    <llaveprivada>    Nombre del archivo en donde esta almancenado el parametro [x]
    <archivo>:        Nombre del archivo con el mensaje a firmar.
    <firma>           Nombre del archivo en donde se almacenara la firma (no colocar extension)
    Ejemplo:    python3 dsa.py sig -p llavepublica.txt -k llaveprivada.txt -m mensaje.txt -s firma
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Riascos          francisco.riascos@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autónoma de Occidente
    Especialización en Seguridad Infromática
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II
================================================================================================================
VERIFICACION DE FIRMA
    Sintaxis: python3 dsa.py ver -p <llavepublica> -m <mensaje> -s <firma>
    <llavepublica>    Nombre del archivo en donde estan almancenados los parametros [p,q,g,y]
    <archivo>:        Nombre del archivo con el mensaje a firmar.
    <firma>           Nombre del archivo en donde esta almacenada la firma.
    Ejemplo:    python dsa.py ver -p llavepublica.txt -m mensaje.txt -s firma.txt
    __________________________________________________________________________________________________
    Autores:    Henry Sarria               henry.sarria@uao.edu.co
                Francisco Riascos          francisco.riascos@uao.edu.co
    __________________________________________________________________________________________________
    Universidad Autónoma de Occidente
    Especialización en Seguridad Infromática
    Certificados y Firmas Digitales
    Siler Amador Donado
    2019-II
================================================================================================================

import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Signature import pss

#AES MODO CBC


#EL VECTOR DE INICIALIZACION ES LA CONTRASEÑA INVERSA, EN SINTESIS.
###OPERACIONES GENERALES

def txtToBytes(ruta):
    archivo = open(ruta, "rb")
    texto = archivo.read()
    archivo.close()
    return texto

def generarLlave():
    caracteres = list(string.ascii_letters + string.digits)
    random.shuffle(caracteres)
    llave_x = []
    for i in range(16):
        llave_x.append(random.choice(caracteres))
    llave = "".join(llave_x)
    return llave
####CIFRADO Y FIRMA#######


##RECIBE rutaMensajeNoFirmado == DONDE ESTA EL TXT ORIGINAL, rutaLlavePrivada == DONDE ESTA LA LLAVE PRIVADA, rutaArchivoFirmado == DONDE SE GUARDARA
##EL ARCHIVO YA FIRMADO, rutaLlaveAGuardar == Ruta donde se va a guardar la llave.
def firma(rutaMensajeNoFirmado, rutaLlavePrivada, rutaNuevoArchivoFirmado, rutaLlaveAGuardar):
    message = txtToBytes(rutaMensajeNoFirmado)
    #Genera una llave de tamaño 16
    llave = generarLlave()
    print("Tu llave es " + llave)
    f = open(rutaLlaveAGuardar, "w")
    f.write(llave)
    f.close()
    print("Llave guardada en: " + rutaLlaveAGuardar)
    key = RSA.import_key(open(rutaLlavePrivada).read())
    h = SHA1.new(message)
    signature = pss.new(key).sign(h)
    contenido_firma = signature + message
    cifrarFirmado(llave, contenido_firma, rutaNuevoArchivoFirmado)
    print("realizado")


def imprimirFirma(contenido, rutaArchivoFirmado):
    arc = open(rutaArchivoFirmado, 'wb')
    arc.write(contenido)
    print("Archivo firmado con exito")
    arc.close()

def cifrarFirmado (llave, contenido, rutaArchivoCifrado):
    llave_b = bytes(llave, 'utf-8')
    iv_b = bytes(llave[::-1], 'utf-8')
    cifradoCBC = AES.new(llave_b, AES.MODE_CBC, iv_b)
    bytesCifrados = cifradoCBC.encrypt(pad(contenido, AES.block_size))
    imprimirFirma(bytesCifrados, rutaArchivoCifrado)

#firma("", "", "", "aqui va mi llave de 16 bytes")


##DESCIFRADO Y VERIFICACION
#AES MODO CBC
#RECIBE LA LLAVE EN FORMATO CLARO, ES DECIR NO EN RUTA, rutaArchivoCifrado == Donde esta guardado el archivo cifrado, rutaLlavePublica == Donde esta
#guardada la llave publica
def descifrarFirmado(llave, rutaArchivoCifrado, rutaLlavePublica):
    llave_b = bytes(llave, 'utf-8')
    iv_b = bytes(llave[::-1], 'utf-8')
    #bytesDescifrados = descifradoCBC.decrypt(pad(contenido, AES.block_size))
    try:
        descifradoCBC = AES.new(llave_b, AES.MODE_CBC, iv_b)
        contenido = txtToBytes(rutaArchivoCifrado)
        print("Cifrado bytes:" + str(len(contenido)))
        bytesDescifrados = unpad(descifradoCBC.decrypt(contenido), AES.block_size)

        verificarFirma(bytesDescifrados, rutaLlavePublica)
    except():
        print("Contraseña no valida")

def verificarFirma(contenido, rutaLlavePublica):
    key = RSA.import_key(open(rutaLlavePublica, 'rb').read())
    h = SHA1.new(contenido[128:])
    verifier = pss.new(key)
    try:
        verifier.verify(h, contenido[0:128])
        print("La firma es autentica")
    except(ValueError, TypeError):
        print("La firma no es autentica.")


##FIRMA RECIBE 1. RUTA DEL MENSAJE EN CLARO 2. RUTA DE LA LLAVE PRIVADA 3. RUTA DONDE GUARDAR EL ARCHIVO CIFRADO
# 4.RUTA DONDE GUARDAR LA LLAVE GENERADA
firma('mensaje.txt','llaveprivadaAlicia.der', 'mensajeC.txt', 'millave.txt')


try:
    #RECIBE LA LLAVE EN FORMATO STRING, NO ARCHIVO . 2. RUTA DEL MENSAJE CIFRADO 3. RUTA DE LA LLAVE PUBLICA
    descifrarFirmado('1234567890123486', 'mensajeC.txt', 'llavepublicaAlicia.der')
except:
    print("Contraseña no valida")

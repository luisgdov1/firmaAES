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

####CIFRADO Y FIRMA#######


##RECIBE rutaMensajeNoFirmado == DONDE ESTA EL TXT ORIGINAL, rutaLlavePrivada == DONDE ESTA LA LLAVE PRIVADA, rutaArchivoFirmado == DONDE SE GUARDARA
##EL ARCHIVO YA FIRMADO y LLAVE= la llave de 16 bytes que genera
def firma(rutaMensajeNoFirmado, rutaLlavePrivada, rutaNuevoArchivoFirmado, llave):
    message = txtToBytes(rutaMensajeNoFirmado)
    key = RSA.import_key(open(rutaLlavePrivada).read())
    h = SHA1.new(message)
    signature = pss.new(key).sign(h)
    contenido_firma = signature + message
    print("Tamaño firma             :" + str(len(signature)))
    print("Tamaño mensaje           :" + str(len(message)))
    print("Tamaño total de contenido:" + str(len(contenido_firma)))
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

firma('mensaje.txt','llaveprivadaAlicia.der', 'mensajeC.txt', '1234567890123456')

descifrarFirmado('1234567890123456', 'mensajeC.txt', 'llavepublicaAlicia.der')
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os
import getpass


def derivar_clave_desde_password(password, salt=None):
    """Deriva una clave criptográfica desde una contraseña"""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    clave = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return clave, salt


def cifrar_con_password(archivo, password):
    """Cifra un archivo usando una contraseña"""
    clave, salt = derivar_clave_desde_password(password)

    with open(archivo, "rb") as f:
        datos = f.read()

    fernet = Fernet(clave)
    datos_cifrados = fernet.encrypt(datos)

    archivo_salida = archivo + ".locked"
    with open(archivo_salida, "wb") as f:
        f.write(salt)
        f.write(datos_cifrados)

    print(f"✓ Archivo cifrado con contraseña: {archivo_salida}")


def descifrar_con_password(archivo_cifrado, password):
    """Descifra un archivo usando una contraseña"""
    with open(archivo_cifrado, "rb") as f:
        salt = f.read(16)
        datos_cifrados = f.read()

    clave, _ = derivar_clave_desde_password(password, salt)

    fernet = Fernet(clave)
    try:
        datos = fernet.decrypt(datos_cifrados)
        archivo_salida = archivo_cifrado.replace(".locked", ".unlocked")
        with open(archivo_salida, "wb") as f:
            f.write(datos)
        print(f"✓ Archivo descifrado: {archivo_salida}")
        return True
    except:
        print("✗ Contraseña incorrecta o archivo dañado")
        return False


if __name__ == "__main__":
    print("=== PROGRAMA DE CIFRADO / DESCIFRADO CON CONTRASEÑA ===")
    print("1. Cifrar un archivo")
    print("2. Descifrar un archivo")

    opcion = input("Selecciona una opción (1 o 2): ").strip()

    if opcion == "1":
        archivo = input("Nombre del archivo a cifrar: ").strip()
        if not os.path.exists(archivo):
            print("✗ El archivo no existe.")
        else:
            password = getpass.getpass("Introduce una contraseña para cifrar: ")
            cifrar_con_password(archivo, password)

    elif opcion == "2":
        archivo = input("Nombre del archivo a descifrar (.locked): ").strip()
        if not os.path.exists(archivo):
            print("✗ El archivo no existe.")
        else:
            password = getpass.getpass("Introduce la contraseña para descifrar: ")
            descifrar_con_password(archivo, password)

    else:
        print("✗ Opción no válida. Debe ser 1 o 2.")

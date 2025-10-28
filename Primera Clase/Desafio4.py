from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os
import getpass  # ← agregado para ocultar la contraseña


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
        print("✗ Contraseña incorrecta")
        return False


if __name__ == "__main__":
    # Crear archivo secreto
    with open("secreto.txt", "w") as f:
        f.write("Información ultra secreta protegida por contraseña")

    print("=== CIFRADO CON CONTRASEÑA ===")
    password = getpass.getpass("Introduce una contraseña para cifrar el archivo: ")
    cifrar_con_password("secreto.txt", password)

    print("\n=== DESCIFRADO CON CONTRASEÑA ===")
    password_descifrado = getpass.getpass("Introduce la contraseña para descifrar el archivo: ")
    descifrar_con_password("secreto.txt.locked", password_descifrado)

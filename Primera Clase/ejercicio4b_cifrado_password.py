from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os


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
    # Derivar clave desde password
    clave, salt = derivar_clave_desde_password(password)
   
    # Leer archivo
    with open(archivo, "rb") as f:
        datos = f.read()
   
    # Cifrar
    f = Fernet(clave)
    datos_cifrados = f.encrypt(datos)
 
    # Guardar salt + datos cifrados
    archivo_salida = archivo + ".locked"
    with open(archivo_salida, "wb") as f:
        f.write(salt)  # Primeros 16 bytes
        f.write(datos_cifrados)
    print(f"✓ Archivo cifrado con contraseña: {archivo_salida}")


def descifrar_con_password(archivo_cifrado, password):
    """Descifra un archivo usando una contraseña"""

    # Leer salt y datos cifrados
    with open(archivo_cifrado, "rb") as f:
        salt = f.read(16)
        datos_cifrados = f.read()

    # Derivar clave desde password
    clave, _ = derivar_clave_desde_password(password, salt)

    # Descifrar
    f = Fernet(clave)
    try:
        datos = f.decrypt(datos_cifrados)
        # Guardar
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
    # Cifrar con contraseña
    print("=== CIFRADO CON CONTRASEÑA ==")
    password = "MiPasswordSeguro2024!"
    cifrar_con_password("secreto.txt", password)

    # Descifrar con contraseña correcta
    print("\n=== DESCIFRADO CON CONTRASEÑA CORRECTA ===")
    descifrar_con_password("secreto.txt.locked", password)


    # Descifrar con contraseña incorrecta
    print("\n=== DESCIFRADO CON CONTRASEÑA INCORRECTA ===")
    descifrar_con_password("secreto.txt.locked", "PasswordIncorrecto")
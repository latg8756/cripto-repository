from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import json
import os
from datetime import datetime
import getpass
import base64

class SistemaMensajeriaSegura:
    def __init__(self, nombre_usuario):
        self.nombre_usuario = nombre_usuario
        self.directorio = f"usuario_{nombre_usuario}"
        if not os.path.exists(self.directorio):
            os.makedirs(self.directorio)
        self.clave_privada = None
        self.clave_publica = None
        self.clave_fernet = None  # clave simétrica para cifrar mensajes locales

    # ==============================================================
    # GESTIÓN DE CLAVES
    # ==============================================================

    def generar_claves(self):
        """Genera par de claves RSA para el usuario"""
        self.clave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.clave_publica = self.clave_privada.public_key()

        # Guardar clave privada
        pem_privada = self.clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(f"{self.directorio}/clave_privada.pem", "wb") as f:
            f.write(pem_privada)

        # Guardar clave pública
        pem_publica = self.clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(f"{self.directorio}/clave_publica.pem", "wb") as f:
            f.write(pem_publica)
        print(f"✓ Claves generadas para {self.nombre_usuario}")

    def cargar_claves(self):
        """Carga las claves del usuario"""
        with open(f"{self.directorio}/clave_privada.pem", "rb") as f:
            self.clave_privada = serialization.load_pem_private_key(f.read(), password=None)
        with open(f"{self.directorio}/clave_publica.pem", "rb") as f:
            self.clave_publica = serialization.load_pem_public_key(f.read())
        print(f"✓ Claves cargadas para {self.nombre_usuario}")

    def cargar_clave_publica_destinatario(self, nombre_destinatario):
        with open(f"usuario_{nombre_destinatario}/clave_publica.pem", "rb") as f:
            return serialization.load_pem_public_key(f.read())

    # ==============================================================
    # CIFRADO LOCAL DE ARCHIVOS DE MENSAJES
    # ==============================================================

    def configurar_clave_local(self):
        """Configura o carga una clave Fernet local derivada de contraseña"""
        password = getpass.getpass("Introduce una contraseña local para cifrar mensajes: ")
        salt_path = f"{self.directorio}/salt.bin"

        if os.path.exists(salt_path):
            with open(salt_path, "rb") as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(salt_path, "wb") as f:
                f.write(salt)

        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        clave = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.clave_fernet = Fernet(clave)

    def guardar_mensaje_cifrado(self, ruta, contenido_json):
        """Guarda el mensaje cifrado localmente"""
        datos = json.dumps(contenido_json, indent=2).encode()
        datos_cifrados = self.clave_fernet.encrypt(datos)
        with open(ruta, "wb") as f:
            f.write(datos_cifrados)

    def leer_mensaje_cifrado(self, ruta):
        """Lee y descifra un mensaje cifrado local"""
        with open(ruta, "rb") as f:
            datos_cifrados = f.read()
        datos = self.clave_fernet.decrypt(datos_cifrados)
        return json.loads(datos.decode())

    # ==============================================================
    # MENSAJERÍA
    # ==============================================================

    def enviar_mensaje(self, destinatario, mensaje):
        """Envía un mensaje cifrado usando cifrado híbrido"""
        print(f"\n--- {self.nombre_usuario} enviando mensaje a {destinatario} --")
        clave_simetrica = Fernet.generate_key()
        f = Fernet(clave_simetrica)
        mensaje_cifrado = f.encrypt(mensaje.encode())

        clave_publica_dest = self.cargar_clave_publica_destinatario(destinatario)
        clave_simetrica_cifrada = clave_publica_dest.encrypt(
            clave_simetrica,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        firma = self.clave_privada.sign(
            mensaje_cifrado,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        paquete = {
            "remitente": self.nombre_usuario,
            "destinatario": destinatario,
            "timestamp": datetime.now().isoformat(),
            "clave_cifrada": clave_simetrica_cifrada.hex(),
            "mensaje_cifrado": mensaje_cifrado.decode(),
            "firma": firma.hex()
        }

        ruta = f"usuario_{destinatario}/mensaje_de_{self.nombre_usuario}.json.enc"
        self.guardar_mensaje_cifrado(ruta, paquete)
        print(f"✓ Mensaje enviado y guardado cifrado en {ruta}")

    def recibir_mensaje(self, remitente):
        """Recibe y descifra un mensaje"""
        print(f"\n--- {self.nombre_usuario} recibiendo mensaje de {remitente} --")
        ruta = f"{self.directorio}/mensaje_de_{remitente}.json.enc"
        paquete = self.leer_mensaje_cifrado(ruta)

        clave_simetrica_cifrada = bytes.fromhex(paquete["clave_cifrada"])
        clave_simetrica = self.clave_privada.decrypt(
            clave_simetrica_cifrada,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        f = Fernet(clave_simetrica)
        mensaje_cifrado = paquete["mensaje_cifrado"].encode()
        mensaje_descifrado = f.decrypt(mensaje_cifrado).decode()

        clave_publica_rem = self.cargar_clave_publica_destinatario(remitente)
        firma = bytes.fromhex(paquete["firma"])
        try:
            clave_publica_rem.verify(
                firma,
                mensaje_cifrado,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print("✓ Firma verificada - Mensaje auténtico")
        except:
            print("✗ Firma inválida - posible alteración")
            return

        print(f"\nDe: {paquete['remitente']}")
        print(f"Fecha: {paquete['timestamp']}")
        print(f"Mensaje: {mensaje_descifrado}")

    def listar_mensajes(self):
        """Lista todos los mensajes recibidos por el usuario"""
        print(f"\n--- Mensajes recibidos por {self.nombre_usuario} ---")
        archivos = [f for f in os.listdir(self.directorio) if f.startswith("mensaje_de_") and f.endswith(".json.enc")]
        if not archivos:
            print("No hay mensajes.")
            return
        for archivo in archivos:
            ruta = os.path.join(self.directorio, archivo)
            try:
                paquete = self.leer_mensaje_cifrado(ruta)
                print(f"• {archivo} - De: {paquete['remitente']} ({paquete['timestamp']})")
            except Exception as e:
                print(f"✗ Error leyendo {archivo}: {e}")

# ==============================================================
# MENÚ INTERACTIVO
# ==============================================================

def menu_interactivo():
    nombre = input("Introduce tu nombre de usuario: ").strip()
    usuario = SistemaMensajeriaSegura(nombre)

    while True:
        print("\n=== MENÚ DE MENSAJERÍA SEGURA ===")
        print("1. Generar claves RSA")
        print("2. Cargar claves existentes")
        print("3. Configurar clave local")
        print("4. Enviar mensaje")
        print("5. Recibir mensaje")
        print("6. Listar mensajes recibidos")
        print("0. Salir")

        opcion = input("Selecciona una opción: ").strip()

        if opcion == "1":
            usuario.generar_claves()
        elif opcion == "2":
            usuario.cargar_claves()
        elif opcion == "3":
            usuario.configurar_clave_local()
        elif opcion == "4":
            dest = input("Nombre del destinatario: ").strip()
            mensaje = input("Mensaje a enviar: ")
            usuario.enviar_mensaje(dest, mensaje)
        elif opcion == "5":
            rem = input("Nombre del remitente: ").strip()
            usuario.recibir_mensaje(rem)
        elif opcion == "6":
            usuario.listar_mensajes()
        elif opcion == "0":
            print("Saliendo del sistema...")
            break
        else:
            print("Opción inválida.")

if __name__ == "__main__":
    menu_interactivo()

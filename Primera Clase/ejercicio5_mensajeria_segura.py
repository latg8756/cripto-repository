from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import json
import os


from datetime import datetime
class SistemaMensajeriaSegura:
    def __init__(self, nombre_usuario):
        self.nombre_usuario = nombre_usuario
        self.directorio = f"usuario_{nombre_usuario}"
        # Crear directorio del usuario
        if not os.path.exists(self.directorio):
            os.makedirs(self.directorio)
        self.clave_privada = None
        self.clave_publica = None
    def generar_claves(self):
        """Genera par de claves RSA para el usuario"""
        self.clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
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
            self.clave_privada = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        with open(f"{self.directorio}/clave_publica.pem", "rb") as f:
            self.clave_publica = serialization.load_pem_public_key(f.read())
        print(f"✓ Claves cargadas para {self.nombre_usuario}")

    def cargar_clave_publica_destinatario(self, nombre_destinatario):
        """Carga la clave pública de otro usuario"""
        with open(f"usuario_{nombre_destinatario}/clave_publica.pem", "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def enviar_mensaje(self, destinatario, mensaje):
        """
        Envía un mensaje cifrado usando cifrado híbrido:
        1. Genera clave simétrica aleatoria
        2. Cifra el mensaje con la clave simétrica (rápido)
        3. Cifra la clave simétrica con la clave pública del destinatario
        4. Firma el mensaje con la clave privada del remitente
        """
        print(f"\n--- {self.nombre_usuario} enviando mensaje a {destinatario} --")
        # 1. Generar clave simétrica para este mensaje
        clave_simetrica = Fernet.generate_key()
        f = Fernet(clave_simetrica)

        # 2. Cifrar mensaje con clave simétrica
        mensaje_cifrado = f.encrypt(mensaje.encode())

        # 3. Cargar clave pública del destinatario y cifrar la clave simétrica
        clave_publica_dest = self.cargar_clave_publica_destinatario(destinatario)
        clave_simetrica_cifrada = clave_publica_dest.encrypt(
            clave_simetrica,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 4. Firmar el mensaje con nuestra clave privada
        firma = self.clave_privada.sign(
            mensaje_cifrado,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # 5. Crear paquete de mensaje
        paquete = {
            "remitente": self.nombre_usuario,
            "destinatario": destinatario,
            "timestamp": datetime.now().isoformat(),
            "clave_cifrada": clave_simetrica_cifrada.hex(),
            "mensaje_cifrado": mensaje_cifrado.decode(),
            "firma": firma.hex()
        }

        # 6. Guardar en bandeja del destinatario
        archivo_mensaje = f"usuario_{destinatario}/mensaje_de_{self.nombre_usuario}.json"
        with open(archivo_mensaje, "w") as f:
            json.dump(paquete, f, indent=2)
        print(f"✓ Mensaje enviado y guardado en {archivo_mensaje}")

    def recibir_mensaje(self, remitente):
        """
        Recibe y descifra un mensaje:
        1. Lee el paquete del mensaje
        2. Descifra la clave simétrica con nuestra clave privada
        3. Descifra el mensaje con la clave simétrica
        4. Verifica la firma con la clave pública del remitente
        """
        print(f"\n--- {self.nombre_usuario} recibiendo mensaje de {remitente} --")

        # 1. Leer paquete
        archivo_mensaje = f"{self.directorio}/mensaje_de_{remitente}.json"
        with open(archivo_mensaje, "r") as f:
            paquete = json.load(f)
        # 2. Descifrar clave simétrica con nuestra clave privada
        clave_simetrica_cifrada = bytes.fromhex(paquete["clave_cifrada"])
        clave_simetrica = self.clave_privada.decrypt(
            clave_simetrica_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # 3. Descifrar mensaje con clave simétrica
        f = Fernet(clave_simetrica)
        mensaje_cifrado = paquete["mensaje_cifrado"].encode()
        mensaje_descifrado = f.decrypt(mensaje_cifrado).decode()
        # 4. Verificar firma con clave pública del remitente
        clave_publica_rem = self.cargar_clave_publica_destinatario(remitente)
        firma = bytes.fromhex(paquete["firma"])
        try:
            clave_publica_rem.verify(
                firma,
                mensaje_cifrado,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("✓ Firma verificada - Mensaje auténtico")
        except:
            print("✗ ADVERTENCIA: Firma inválida - Mensaje puede estar alterado")
            return None
        # 5. Mostrar información del mensaje
        print(f"\nDe: {paquete['remitente']}")
        print(f"Fecha: {paquete['timestamp']}")
        print(f"Mensaje: {mensaje_descifrado}")
        return mensaje_descifrado
def demostrar_sistema():
    """Demostración completa del sistema de mensajería"""
    print("="*60)
    print("SISTEMA DE MENSAJERÍA SEGURA")
    print("="*60)
    # Crear dos usuarios: Alicia y Bob
    print("\n### Paso 1: Crear usuarios y generar claves ###")
    alicia = SistemaMensajeriaSegura("Alicia")
    alicia.generar_claves()
    bob = SistemaMensajeriaSegura("Bob")
    bob.generar_claves()
    # Alicia envía mensaje a Bob
    print("\n### Paso 2: Alicia envía mensaje cifrado a Bob ###")
    mensaje_secreto = "Hola Bob, nos vemos en el lugar secreto a las 15:00. Trae los documentos."
    alicia.enviar_mensaje("Bob", mensaje_secreto)

    # Bob recibe y descifra el mensaje
    print("\n### Paso 3: Bob recibe y descifra el mensaje ###")
    bob.cargar_claves()
    mensaje_recibido = bob.recibir_mensaje("Alicia")
    # Bob responde a Alicia
    print("\n### Paso 4: Bob responde a Alicia ###")
    respuesta = "Entendido Alicia, ahí estaré con todo preparado."
    bob.enviar_mensaje("Alicia", respuesta)
    # Alicia recibe la respuesta
    print("\n### Paso 5: Alicia recibe la respuesta ###")
    alicia.cargar_claves()
    alicia.recibir_mensaje("Bob")
    print("\n" + "="*60)
    print("DEMOSTRACIÓN COMPLETADA")
    print("="*60)
    print("\nConceptos aplicados:")
    print("✓ Cifrado híbrido (RSA + Fernet)")
    print("✓ Gestión de claves pública/privada")
    print("✓ Firmas digitales para autenticación")
    print("✓ Verificación de integridad")
    print("✓ Almacenamiento seguro de mensajes")

if __name__ == "__main__":
    demostrar_sistema()
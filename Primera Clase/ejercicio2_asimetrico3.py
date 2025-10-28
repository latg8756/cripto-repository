from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def cargar_clave_publica():
  """Carga la clave pública desde archivo""" 
  with open("clave_publica.pem", "rb") as f:
    clave_publica = serialization.load_pem_public_key(f.read()) 
  return clave_publica

def cargar_clave_privada():
  """Carga la clave privada desde archivo""" 
  with open("clave_privada.pem", "rb") as f:
    clave_privada = serialization.load_pem_private_key(
    f.read(),
    password=None
   )
  return clave_privada

def cifrar_con_clave_publica(mensaje, clave_publica): 
  """Cifra un mensaje con la clave pública"""
  mensaje_bytes = mensaje.encode()

  mensaje_cifrado = clave_publica.encrypt( 
    mensaje_bytes,
    padding.OAEP(
      mgf=padding.MGF1(algorithm=hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None
    )
  )
   
  print(f"\nMensaje original: {mensaje}")
  print(f"Mensaje cifrado (primeros 50 bytes): {mensaje_cifrado[:50].hex ()}...")
  return mensaje_cifrado

def descifrar_con_clave_privada(mensaje_cifrado, clave_privada):
  """Descifra un mensaje con la clave privada"""
  mensaje_descifrado = clave_privada.decrypt( 
    mensaje_cifrado,
    padding.OAEP(
      mgf=padding.MGF1(algorithm=hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None
    )
  )

  print(f"Mensaje descifrado: {mensaje_descifrado.decode()}")
  return mensaje_descifrado.decode()



def generar_par_claves():
  """Genera un par de claves RSA"""
  # Generar clave privada
  clave_privada = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
  ) 

  # Obtener clave pública
  clave_publica = clave_privada.public_key()
  
  # Serializar clave privada
  pem_privada = clave_privada.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
  )

  # Serializar clave pública
  pem_publica = clave_publica.public_bytes(
   encoding=serialization.Encoding.PEM,        
   format=serialization.PublicFormat.SubjectPublicKeyInfo
  )

  # Guardar claves
  with open("clave_privada.pem", "wb") as f: 
    f.write(pem_privada)

  with open("clave_publica.pem", "wb") as f: 
    f.write(pem_publica)
   
  print("✓ Par de claves RSA generado")
  print(" - clave_privada.pem (MANTENER SEGURA)")
  print(" - clave_publica.pem (se puede compartir)")
  return clave_privada, clave_publica

if __name__ == "__main__":

   print("=== GENERACIÓN DE CLAVES ===")
   clave_privada, clave_publica = generar_par_claves()

   print("\n=== SIMULACIÓN: Alicia envía un mensaje a Bob ===")
   print("Bob comparte su clave pública con Alicia")

   # Alicia usa la clave pública de Bob para cifrar 
   mensaje = "Reunión secreta mañana a las 10:00 hola esta es una prueba de mas de 190 caracteres, modulo 3 de ciberseguridad de Anahuac, nos vemos proximamente en otro diplomado, estuvieron muy bien las practicas"
   mensaje_cifrado = cifrar_con_clave_publica(mensaje, clave_publica)

   # El mensaje cifrado viaja por Internet... 
   print("\n[Mensaje cifrado en tránsito...]")

   # Bob usa su clave privada para descifrar
   print("\n=== Bob recibe y descifra el mensaje ===") 
   descifrar_con_clave_privada(mensaje_cifrado,clave_privada)

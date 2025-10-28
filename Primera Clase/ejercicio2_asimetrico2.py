from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes




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
    generar_par_claves()
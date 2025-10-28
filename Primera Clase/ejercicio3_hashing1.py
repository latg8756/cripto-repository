import hashlib
import os

def hash_password(password, salt=None):
  """Crea un hash seguro de una contraseña con salt""" 
  if salt is None:
     salt = os.urandom(32)

  # Usar PBKDF2 para hacer el hash más resistente a ataques 
  hash_obj = hashlib.pbkdf2_hmac(
    'sha256',
    password.encode(),
    salt,
    100000 # 100,000 iteraciones
  )
  return salt, hash_obj

def verificar_password(password_ingresado, salt, hash_guardado):    
  """Verifica si una contraseña coincide con el hash guardado"""
  _, hash_nuevo = hash_password(password_ingresado, salt) 
  return hash_nuevo == hash_guardado


def calcular_hash_sha256(datos):
  """Calcula el hash SHA-256 de los datos""" 
  if isinstance(datos, str):
      datos = datos.encode()
  hash_obj = hashlib.sha256(datos) 
  return hash_obj.hexdigest()

def verificar_integridad(archivo, hash_esperado):
  """Verifica si el hash de un archivo coincide con el esperado""" 
  with open(archivo, "rb") as f:
    contenido = f.read()
    hash_calculado = calcular_hash_sha256(contenido)
  
  if hash_calculado == hash_esperado:
     print(f"✓ Integridad verificada para {archivo}") 
     return True
  else:
     print(f"✗ ADVERTENCIA: {archivo} ha sido modificado")
     print(f" Hash esperado: {hash_esperado}")
     print(f" Hash calculado: {hash_calculado}")
     return False

if __name__ == "__main__":
    # Crear un archivo de prueba
    contenido_original = "Este es un documento importante que no debe ser modificado"

    with open("documento.txt", "w") as f:
      f.write(contenido_original)
   
    # Calcular y guardar el hash
    hash_original = calcular_hash_sha256(contenido_original)
    print(f"Hash del documento: {hash_original}")
   
    with open("documento.hash", "w") as f:
      f.write(hash_original)

    print("\n--- Verificación de integridad ---")
    verificar_integridad("documento.txt", hash_original)


    # Simular modificación del archivo
    print("\n--- Simulando modificación del archivo ---") 
    with open("documento.txt", "a") as f:
      f.write(".") # Añadir un solo punto

    # Intentar verificar nuevamente 
    print("\n--- Nueva verificación ---")
    verificar_integridad("documento.txt", hash_original)

    # Prueba
    print("\n=== GESTIÓN SEGURA DE CONTRASEÑAS ===")
    password_usuario = "MiContraseñaSegura123!"

    salt, hash_pwd = hash_password(password_usuario) 
    print(f"✓ Contraseña hasheada correctamente") 
    print(f"Salt (hex): {salt.hex()[:32]}...")
    print(f"Hash (hex): {hash_pwd.hex()[:32]}...")

    # Verificar contraseña correcta 
    print("\nVerificando contraseña correcta...")
    if verificar_password("MiContraseñaSegura123!", salt, hash_pwd):
       print("✓ Acceso permitido")

    # Verificar contraseña incorrecta
    print("\nVerificando contraseña incorrecta...")
    if not verificar_password("ContraseñaIncorrecta", salt, hash_pwd):
       print("✗ Acceso denegado")



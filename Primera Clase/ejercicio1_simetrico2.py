from cryptography.fernet import Fernet
import os


#Generar una clave simetrica

def generar_clave():
    clave = Fernet.generate_key()
    print(f"✓ Clave generada:{clave.decode()}")
   
    #Guarda la clave en un archivo
    with open("clave_simetrica.key","wb") as archivo_clave:
      archivo_clave.write(clave)
    
    print("✓ Clave guardada en 'clave_simetrica.key'")
    return clave

#Cargar una clave existente
def cargar_clave():
  return open("clave_simetrica.key","rb").read()
  
def cifrar_mensaje(mensaje, clave):
  """Cifra un mensaje usando la clave proporcionada""" 
  f = Fernet(clave)
  mensaje_bytes = mensaje.encode()
  mensaje_cifrado = f.encrypt(mensaje_bytes) 
  print(f"\nMensaje original: {mensaje}") 
  print(f"Mensaje cifrado: {mensaje_cifrado.decode()}") 
  return mensaje_cifrado

def descifrar_mensaje(mensaje_cifrado, clave):
  """Descifra un mensaje usando la clave proporcionada"""
  f = Fernet(clave)
  mensaje_descifrado = f.decrypt(mensaje_cifrado) 
  print(f"Mensaje descifrado: {mensaje_descifrado.decode()}")
  return mensaje_descifrado.decode()


if __name__ == "__main__":
    # Generar clave
    clave =  generar_clave()
    
    # Mensaje secreto
    mensaje = "Este es un mensaje confidencial del diplomado de ciberseguridad"
   
    # Cifrar
    mensaje_cifrado = cifrar_mensaje(mensaje,clave)


    # Guardar mensaje cifrado
    with open("mensaje_cifrado.bin", "wb") as f:     
      f.write(mensaje_cifrado)
    print("✓ Mensaje cifrado guardado")


    # Simular que cargamos el mensaje y la clave 
    clave_cargada = cargar_clave()
    with open("mensaje_cifrado.bin", "rb") as f: 
      mensaje_recuperado = f.read()

    # Descifrar
    print("\n--- Proceso de descifrado ---")
    descifrar_mensaje(mensaje_recuperado, clave_cargada)



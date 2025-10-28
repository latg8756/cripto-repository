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
  
if __name__ == "__main__":
    generar_clave()
    

from cryptography.fernet import Fernet
import os

class CifradorArchivos:
    def __init__(self):
        self.clave = None

    def generar_clave(self, nombre_archivo_clave="archivo.key"):
        """Genera una nueva clave y la guarda"""
        self.clave = Fernet.generate_key()
        with open(nombre_archivo_clave, "wb") as f:
            f.write(self.clave)
        print(f"✓ Clave generada y guardada en {nombre_archivo_clave}")

    def cargar_clave(self, nombre_archivo_clave="archivo.key"):
        """Carga una clave existente"""
        with open(nombre_archivo_clave, "rb") as f:
            self.clave = f.read()
        print(f"✓ Clave cargada desde {nombre_archivo_clave}")
    def cifrar_archivo(self, archivo_entrada):
        """Cifra un archivo completo"""
        if self.clave is None:
            print("✗ Error: Primero debes generar o cargar una clave")
            return
        # Leer el archivo original
        with open(archivo_entrada, "rb") as f:
            datos = f.read()

        # Cifrar los datos
        f = Fernet(self.clave)
        datos_cifrados = f.encrypt(datos)
        
        # Guardar archivo cifrado
        archivo_salida = archivo_entrada + ".encrypted"
        with open(archivo_salida, "wb") as f:
            f.write(datos_cifrados)
        
        print(f"✓ Archivo cifrado: {archivo_salida}")
        print(f"  Tamaño original: {len(datos)} bytes")
        print(f"  Tamaño cifrado: {len(datos_cifrados)} bytes")
    
    def descifrar_archivo(self, archivo_cifrado):
        """Descifra un archivo"""
        if self.clave is None:
            print("✗ Error: Primero debes cargar una clave")
            return

        # Leer archivo cifrado
        with open(archivo_cifrado, "rb") as f:
            datos_cifrados = f.read()
        # Descifrar
        f = Fernet(self.clave)
        try:
            datos_descifrados = f.decrypt(datos_cifrados)
            # Guardar archivo descifrado
            if archivo_cifrado.endswith(".encrypted"):
                archivo_salida = archivo_cifrado[:-10]  # Quitar .encrypted
            else:
                archivo_salida = archivo_cifrado + ".decrypted"
            with open(archivo_salida, "wb") as f:
                f.write(datos_descifrados)
            print(f"✓ Archivo descifrado: {archivo_salida}")
        except Exception as e:
            print(f"✗ Error al descifrar: {e}")
            print("  Verifica que estés usando la clave correcta")

if __name__ == "__main__":
    # Crear un archivo de prueba
    print("=== Creando archivo de prueba ===")
    with open("confidencial.txt", "w") as f:
        f.write("Información altamente confidencial\n")
        f.write("Usuario: admin\n")
        f.write("Contraseña: SuperSecreta123\n")
        f.write("Datos financieros importantes...")
    print("✓ Archivo 'confidencial.txt' creado")
    # Usar el sistema de cifrado
    print("\n=== CIFRANDO ARCHIVO ===")
    cifrador = CifradorArchivos()
    cifrador.generar_clave()
    cifrador.cifrar_archivo("confidencial.txt")
    print("\n=== DESCIFRANDO ARCHIVO ===")
    descifrador = CifradorArchivos()
    descifrador.cargar_clave()
    descifrador.descifrar_archivo("confidencial.txt.encrypted")
    print("\n=== Verificación ===")
    print("Puedes comparar los archivos:")
    print("  - confidencial.txt (original)")
    print("  - confidencial.txt.encrypted (cifrado)")
    print("  - confidencial.txt (descifrado)")

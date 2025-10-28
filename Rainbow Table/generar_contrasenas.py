#!/usr/bin/env python3
"""
hash_contrasenas_mostrar.py

Lee contraseñas desde un archivo "contrasenas" (una por línea),
calcula su hash SHA-256 (opcionalmente con salt) y guarda los hashes
en el archivo "Diccionario.txt" (una línea por hash). Finalmente
muestra el contenido de "Diccionario.txt".
"""

import hashlib
from pathlib import Path
import tempfile
import os
from typing import List, Iterable, Optional
import argparse

DEFAULT_INPUT = Path("contrasenas.txt")
DEFAULT_OUTPUT = Path("Diccionario.txt")
DEFAULT_PERMS = 0o600  # rw-------


def leer_contrasenas(path: Path) -> List[str]:
    """Lee contraseñas desde 'path', devuelve lista sin líneas vacías ni espacios extras."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {path}")
    with path.open("r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def sha256_hexdigest(text: str) -> str:
    """Devuelve el SHA-256 hex digest de 'text'."""
    h = hashlib.sha256()
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def generar_hashes(contrasenas: Iterable[str], salt: Optional[str] = None) -> List[str]:
    """
    Genera hashes SHA-256 para cada contraseña.
    Si 'salt' está presente, se concatenará como salt + contraseña antes de hashear.
    """
    salt = salt or ""
    hashes = []
    for pwd in contrasenas:
        combined = salt + pwd
        hashes.append(sha256_hexdigest(combined))
    return hashes


def guardar_lineas_atomic(path: Path, lineas: Iterable[str], mode: int = DEFAULT_PERMS) -> None:
    """
    Guarda las líneas en 'path' de forma atómica usando un archivo temporal en el mismo directorio.
    Ajusta permisos del archivo final a 'mode'.
    """
    path = Path(path)
    parent = path.parent or Path(".")
    parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", dir=str(parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for line in lineas:
                f.write(line + "\n")
        os.replace(tmp_path, str(path))
        os.chmod(str(path), mode)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def mostrar_contenido(path: Path) -> None:
    """Muestra el contenido de 'path' con numeración de líneas. Si no existe, avisa."""
    path = Path(path)
    if not path.exists():
        print(f"(El archivo {path} no existe.)")
        return
    print(f"\nContenido de {path}:")
    try:
        with path.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                print(f"{i:02d}: {line.rstrip()}")
    except Exception as e:
        print(f"Error leyendo {path}: {e}")


def parse_args():
    parser = argparse.ArgumentParser(description="Genera SHA-256 de contraseñas desde un archivo y muestra el Diccionario.")
    parser.add_argument("--input", "-i", type=str, default=str(DEFAULT_INPUT),
                        help="Archivo de entrada con contraseñas (una por línea).")
    parser.add_argument("--output", "-o", type=str, default=str(DEFAULT_OUTPUT),
                        help="Archivo de salida donde se guardan los hashes.")
    parser.add_argument("--salt", "-s", type=str, default="",
                        help="Salt opcional a concatenar antes de cada contraseña (por defecto: sin salt).")
    parser.add_argument("--perms", type=lambda x: int(x, 8), default=DEFAULT_PERMS,
                        help="Permisos octales para el archivo de salida (por ejemplo: 0o600).")
    return parser.parse_args()


def main():
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    salt = args.salt
    perms = args.perms

    try:
        contrasenas = leer_contrasenas(input_path)
    except Exception as e:
        print("Error leyendo archivo de contraseñas:", e)
        return

    if not contrasenas:
        print("No se encontraron contraseñas en el archivo de entrada.")
        # Crear/limpiar el archivo de salida vacío
        guardar_lineas_atomic(output_path, [], mode=perms)
        mostrar_contenido(output_path)
        return

    hashes = generar_hashes(contrasenas, salt=salt)

    try:
        guardar_lineas_atomic(output_path, hashes, mode=perms)
    except Exception as e:
        print("Error guardando archivo de hashes:", e)
        return

    print(f"Procesadas {len(hashes)} contraseñas.")
    print(f"Hashes guardados en: {output_path} (permisos: {oct(perms)})")

    # Mostrar contenido del archivo resultante
    mostrar_contenido(output_path)


if __name__ == "__main__":
    main()

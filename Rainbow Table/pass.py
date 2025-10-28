#!/usr/bin/env python3
"""
crear_hashear_buscar.py

Interactivo:
  - Pide n contraseñas (entrada oculta)
  - Guarda contraseñas en "contrasenas.txt"
  - Calcula SHA-256 de cada contraseña y guarda "contraseña:hash" en "Diccionario.txt"
  - Muestra el contenido de "Diccionario.txt"
  - Pide un hash al usuario y busca coincidencias en "Diccionario.txt" (formato contraseña:hash)
    mostrando la(s) contraseña(s) asociada(s) si las hay.
"""

from pathlib import Path
import tempfile
import os
import hashlib
from typing import List, Iterable, Tuple
import getpass
import sys

CONTRASENAS_FILE = Path("contrasenas.txt")
DICCIONARIO_FILE = Path("Diccionario.txt")
DEFAULT_PERMS = 0o600  # rw-------


def escribir_lineas_atomic(path: Path, lineas: Iterable[str], mode: int = DEFAULT_PERMS) -> None:
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


def leer_contrasenas(path: Path) -> List[str]:
    path = Path(path)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def sha256_hexdigest(text: str) -> str:
    h = hashlib.sha256()
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def generar_pares(contrasenas: Iterable[str]) -> List[str]:
    pares = []
    for pwd in contrasenas:
        pares.append(f"{pwd}:{sha256_hexdigest(pwd)}")
    return pares


def mostrar_contenido(path: Path) -> None:
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


def pedir_contrasenas_interactivo(n: int) -> List[str]:
    contrasenas: List[str] = []
    print(f"Introduce {n} contraseñas (entrada oculta). Pulsa Ctrl-C para cancelar.")
    for i in range(1, n + 1):
        while True:
            try:
                pwd = getpass.getpass(f"Contraseña {i}/{n}: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nEntrada cancelada por el usuario.")
                raise SystemExit(1)
            if not pwd:
                print("La contraseña no puede estar vacía. Intenta de nuevo.")
                continue
            try:
                pwd2 = getpass.getpass("Confirma la contraseña: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nEntrada cancelada por el usuario.")
                raise SystemExit(1)
            if pwd != pwd2:
                print("No coinciden. Vuelve a introducirla.")
                continue
            contrasenas.append(pwd)
            break
    return contrasenas


def leer_diccionario(path: Path) -> List[Tuple[str, str]]:
    """
    Lee el archivo 'path' con formato 'contraseña:hash' y devuelve lista de tuplas (pwd, hash).
    Normaliza el hash a minúsculas. Ignora líneas malformadas.
    """
    entries: List[Tuple[str, str]] = []
    path = Path(path)
    if not path.exists():
        return entries
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n").strip()
            if not line or ":" not in line:
                continue
            pwd, h = line.split(":", 1)
            pwd = pwd.strip()
            h = h.strip().lower()
            if not pwd or not h:
                continue
            entries.append((pwd, h))
    return entries


def buscar_passwords_por_hash(target_hash: str, entries: List[Tuple[str, str]]) -> List[str]:
    target = target_hash.strip().lower()
    if not target:
        return []
    return [pwd for (pwd, h) in entries if h == target]


def pedir_hash_y_buscar(dict_path: Path) -> None:
    entries = leer_diccionario(dict_path)
    if not entries:
        print(f"(El archivo {dict_path} no contiene entradas válidas o no existe.)")
        return
    try:
        target_hash = input("\nIntroduce el hash a buscar (hex): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nBúsqueda cancelada.")
        return
    if not target_hash:
        print("No se introdujo ningún hash.")
        return
    matches = buscar_passwords_por_hash(target_hash, entries)
    if not matches:
        print("No se encontraron contraseñas para ese hash.")
    else:
        print(f"Se encontraron {len(matches)} coincidencia(s):")
        for i, pwd in enumerate(matches, start=1):
            print(f"{i:02d}: {pwd}")


def main():
    # Pedir número de contraseñas
    try:
        n_raw = input("¿Cuántas contraseñas quieres introducir? (n): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nEntrada cancelada.")
        return
    if not n_raw.isdigit():
        print("Número no válido. Debe ser un entero positivo.")
        return
    n = int(n_raw)
    if n <= 0:
        print("El número debe ser positivo.")
        return

    # Pedir interactivamente las contraseñas
    contrasenas = pedir_contrasenas_interactivo(n)

    # Guardar en contrasenas.txt (sobrescribe)
    try:
        escribir_lineas_atomic(CONTRASENAS_FILE, contrasenas, mode=DEFAULT_PERMS)
        print(f"\nGuardadas {len(contrasenas)} contraseñas en: {CONTRASENAS_FILE}")
    except Exception as e:
        print("Error guardando contraseñas:", e)
        return

    # Generar pares contraseña:hash y guardar en Diccionario.txt
    pares = generar_pares(contrasenas)
    try:
        escribir_lineas_atomic(DICCIONARIO_FILE, pares, mode=DEFAULT_PERMS)
        print(f"Hashes generados y guardados en: {DICCIONARIO_FILE}")
    except Exception as e:
        print("Error guardando diccionario:", e)
        return

    # Mostrar contenido del Diccionario.txt
    mostrar_contenido(DICCIONARIO_FILE)

    # Pedir un hash al usuario y buscar la(s) contraseña(s) asociada(s)
    pedir_hash_y_buscar(DICCIONARIO_FILE)


if __name__ == "__main__":
    main()

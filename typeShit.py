"""Main CLI scaffold for the TYP3_SH1T project.

This file implements an interactive terminal menu and an argparse entrypoint.
It provides placeholder handlers for future classes (encryption, decryption,
key generation, status). Calls to yet-to-be-created modules are commented where
they will be inserted.

"""

from __future__ import annotations

from typing import Optional


def encriptacionArchivo(input_file: Optional[str], output_file: Optional[str], key: Optional[str], algorithm: Optional[str] = None) -> None:
    """Placeholder: encrypt input_file and write to output_file using key.

    Replace the print statements with calls to your encryption class, e.g.:
        from Algoritmo_Simetrico.Cifrado import Cifrador
        cif = Cifrador(key)
        cif.encrypt_file(input_file, output_file)
    """
    print("[ENCRYPT] Placeholder handler called")
    print(f"  input_file = {input_file}")
    print(f"  output_file = {output_file}")
    print(f"  key = {key}")
    print(f"  algorithm = {algorithm}")


def desencriptarArchivo(input_file: Optional[str], output_file: Optional[str], key: Optional[str], algorithm: Optional[str] = None) -> None:
    """Placeholder: decrypt input_file and write to output_file using key.

    Future implementation example:
        from Algoritmo_Simetrico.Descifrado import Descifrador
        dec = Descifrador(key)
        dec.decrypt_file(input_file, output_file)
    """
    print("[DECRYPT] Placeholder handler called")
    print(f"  input_file = {input_file}")
    print(f"  output_file = {output_file}")
    print(f"  key = {key}")
    print(f"  algorithm = {algorithm}")


def select_algorithm() -> Optional[str]:
    """Sub-menú compartido para seleccionar algoritmo AES.

    Devuelve una cadena representando el algoritmo seleccionado: 'AES-128',
    'AES-192' o 'AES-256'. Si el usuario cancela o introduce una opción inválida,
    puede devolverse None.
    """
    choices = {1: "AES-128", 2: "AES-192", 3: "AES-256", 4: "Cancelar"}
    while True:
        print("\n  Seleccione el algoritmo:")
        for k, v in choices.items():
            print(f"  {k}) {v}")
        try:
            sel = int(input("  Opción [1-4]: ").strip())
        except ValueError:
            print("  Entrada no válida, intente de nuevo.")
            continue

        if sel in choices:
            if sel == 4:
                print("  Operación cancelada por el usuario.")
                print("  [DEBUG] select_algorithm() -> None (cancel)")
                return None
            return choices[sel]
        else:
            print("  Opción fuera de rango, intente de nuevo.")


def generadorDeClave(algorithm: Optional[str]) -> None:
    """Placeholder: generate a key for the selected algorithm.

    Future example:
        from Algoritmo_Simetrico.Keygen import KeyGenerator
        kg = KeyGenerator(algorithm)
        print(kg.generate())
    """
    print("[KEYGEN] Placeholder handler called")
    print(f"  algorithm = {algorithm}")


def handle_status() -> None:
    """Show a quick status of the app/environment.

    This can later check availability of modules, keys on disk, etc.
    """
    print("[STATUS] Application scaffold is healthy")
    # Example quick checks (non-exhaustive):
    try:
        import Algoritmo_Simetrico  # type: ignore
        print("  Algoritmo_Simetrico package: available")
    except Exception:
        print("  Algoritmo_Simetrico package: NOT available (expected during scaffold)")


def interactive_menu() -> None:
    """Simple interactive menu using input()."""
    while True:
        print("\n=== TYP3_SH1T - Menu interactivo ===")
        print("1) Encriptar archivo")
        print("2) Desencriptar archivo")
        print("3) Generar clave")
        print("4) Salir")
        try:
            inputUser = int(input("Seleccione una opción [1-4]: ").strip())
        except ValueError:
            print("Entrada no válida, por favor ingrese un número entre 1 y 4.")
            continue


        options = {1: "encriptar", 2: "desencriptar", 3: "generar clave", 4: "salir"}
        choice = options.get(inputUser)


        if not choice:
            print("Opción no válida, inténtelo de nuevo.")
            continue

        if choice == "encriptar":
            # Primero seleccionamos el algoritmo (submenú compartido)
            algo = select_algorithm()
            if algo is None:
                continue
            # Una vez seleccionado el algoritmo, pedimos archivo y clave
            print("\n")
            in_file = input("  Archivo entrada: ").strip() or None
            key = input("  Clave (o path a clave): ").strip() or None
            # En el futuro, llamaríamos a: Cifrador.encrypt_file(in_file, output_file=None, key=key, algorithm=algo)
            encriptacionArchivo(in_file, None, key, algorithm=algo)
        elif choice == "desencriptar":
            # Primero seleccionamos el algoritmo (submenú compartido)
            algo = select_algorithm()
            if algo is None:
                continue
            in_file = input("  Archivo entrada: ").strip() or None
            key = input("  Clave (o path a clave): ").strip() or None
            # En el futuro: Descifrador.decrypt_file(in_file, output_file=None, key=key, algorithm=algo)
            desencriptarArchivo(in_file, None, key, algorithm=algo)
        elif choice == "generar clave":
            algo = input("  Algoritmo (ej: AES, DES): ").strip() or None
            generadorDeClave(algo)
        elif choice == "salir":
            print("Saliendo...")
            break




def main(argv: Optional[list[str]] = None) -> int:
    """Entrypoint for the application.

    This version forces the interactive menu. Argument parsing is intentionally
    removed: the plan is to get parameters via the interactive menu (or in a
    future GUI).
    """
    interactive_menu()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
    pass
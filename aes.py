from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets

class AES():
    def __init__(self):
        pass

    def encriptar_archivo_AES(self, file_path: str,modeAES: str, key: bytes, key_length_bits: int, output_path: str = None):
        """
        Cifra un archivo usando AES en modo CBC con padding PKCS7.
        
        Parámetros:
            file_path (str): Ruta al archivo a cifrar.
            key (bytes): Clave de cifrado.
            key_length_bits (int): Longitud de clave en bits (por ejemplo 128, 192 o 256).
            output_path (str, opcional): Ruta donde guardar el archivo cifrado. 
                                         Si no se indica, se añade '.enc' al original.

        Excepciones:
            ValueError: Si la clave no coincide con la longitud de bits indicada.
            FileNotFoundError: Si el archivo no existe.
        """

        # --- Validación del tamaño de la clave según el parámetro indicado ---
        expected_bytes = key_length_bits // 8  # conversión de bits a bytes
        if not isinstance(key, (bytes, bytearray)):
            raise ValueError("La clave debe ser de tipo bytes o bytearray.")
        if len(key) != expected_bytes:
            raise ValueError(f"La clave debe tener {expected_bytes} bytes para AES-{key_length_bits} bits.")

        # --- Verificar existencia del archivo ---
        file = Path(file_path)
        if not file.is_file():
            raise FileNotFoundError(f"No existe el archivo: {file_path}")

        # --- Lectura segura del archivo completo (modo binario) ---
        plaintext = file.read_bytes()

        # --- Generar IV aleatorio (vector de inicialización) ---
        # Este IV debe ser único por cada cifrado con la misma clave.
        iv = secrets.token_bytes(16)


        # --- Configurar el objeto de cifrado AES ---
        backend = default_backend()

        modeCipher = modes


        match modeAES:
            case "CBC":  
                modeCipher = modes.CBC(iv)
            
            case "CFB":
                modeCipher = modes.CFB(iv)
        
            case "OFB":
                modeCipher = modes.OFB(iv)
            case _:
                raise ValueError(f"Modo de cifrado no soportado: {modeAES}")
     
        cipher = Cipher(algorithms.AES(key), modeCipher, backend=backend)
        encryptor = cipher.encryptor()

        # --- Aplicar padding PKCS7 ---
        # AES trabaja con bloques de 128 bits (16 bytes) siempre, independientemente del tamaño de la clave.
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # --- Cifrar los datos ---
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        guardarClaveArchivo(key, iv)
        # --- Generar ruta de salida ---
        if not output_path:
            output_path = str(file_path) + ".enc"

        # --- Guardar IV + datos cifrados ---
        # El IV no es secreto, pero debe almacenarse junto con el ciphertext.
        with open(output_path, "wb") as f:
            f.write(iv + ciphertext)

        # --- Intentar eliminar datos sensibles de memoria ---
        try:
            del plaintext, padded_data
        except Exception:
            pass

        print(f"Archivo cifrado correctamente usando AES-{key_length_bits} bits → {output_path}")

    def desencriptar_archivo_AES(self, file_path: str,modeAES : str, key: bytes, key_length_bits: int, output_path: str = None):
        """
        Descifra un archivo cifrado con AES en modo CBC con padding PKCS7.
        
        Parámetros:
            file_path (str): Ruta del archivo cifrado (debe contener IV + datos cifrados).
            key (bytes): Clave de descifrado (misma usada para cifrar).
            key_length_bits (int): Longitud de clave en bits (por ejemplo 128, 192 o 256).
            output_path (str, opcional): Ruta donde guardar el archivo descifrado. 
                                         Si no se indica, se eliminará la extensión '.enc'.

        Excepciones:
            ValueError: Si la clave no coincide con la longitud indicada o el padding es incorrecto.
            FileNotFoundError: Si el archivo no existe.
        """

        # --- Validación del tamaño de la clave según el parámetro indicado ---
        expected_bytes = key_length_bits // 8  # conversión de bits a bytes
        if not isinstance(key, (bytes, bytearray)):
            raise ValueError("La clave debe ser de tipo bytes o bytearray.")
        if len(key) != expected_bytes:
            raise ValueError(f"La clave debe tener {expected_bytes} bytes para AES-{key_length_bits} bits.")

        # --- Comprobar existencia del archivo cifrado ---
        file = Path(file_path)
        if not file.is_file():
            raise FileNotFoundError(f"No existe el archivo: {file_path}")


        # --- Validar que el archivo termine realmente en '.enc' ---
        # Esto evita falsos positivos como 'hola.txt.enc.mp4' o 'algoenc'
        if file.suffix.lower() != ".enc":
            raise ValueError(f"El archivo '{file.name}' no parece ser un archivo cifrado válido (.enc).")

        # --- Leer todo el archivo cifrado ---
        encrypted_data = file.read_bytes()

        # --- Extraer IV (primeros 16 bytes) y ciphertext (resto) ---
        if len(encrypted_data) <= 16:
            raise ValueError("El archivo cifrado es demasiado pequeño o está corrupto.")
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # --- Configurar el objeto de descifrado AES + CBC ---
        backend = default_backend()

        modeCipher = modes


        match modeAES:
            case "CBC":  
                modeCipher = modes.CBC(iv)
            
            case "CFB":
                modeCipher = modes.CFB(iv)
        
            case "OFB":
                modeCipher = modes.OFB(iv)
            case _:
                raise ValueError(f"Modo de cifrado no soportado: {modeAES}")
     
        cipher = Cipher(algorithms.AES(key), modeCipher, backend=backend)   
        decryptor = cipher.decryptor()

        # --- Descifrar los datos ---
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # --- Eliminar padding PKCS7 ---
        unpadder = padding.PKCS7(128).unpadder()
        try:
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError:
            raise ValueError("Error al eliminar padding. Clave incorrecta o archivo dañado.")

        # --- Generar ruta de salida ---
        if not output_path:
            # Si el archivo termina en ".enc", quitamos esa extensión
            output_path = str(file_path)
            output_path = output_path[:-4]
            output_path += ".dec"

        # --- Guardar el archivo descifrado ---
        with open(output_path, "wb") as f:
            f.write(plaintext)

        # --- Intentar eliminar datos sensibles de memoria ---
        try:
            del plaintext, padded_plaintext, ciphertext
        except Exception:
            pass

        print(f"Archivo descifrado correctamente usando AES-{key_length_bits} bits → {output_path}")

def guardarClaveArchivo(key: str, iv: str) -> None:

    file_path = "Keys\\keys.txt"
    with open(file_path, 'a') as f:
        f.write(f"Key: {key.hex()} | IV: {iv.hex()}\n")
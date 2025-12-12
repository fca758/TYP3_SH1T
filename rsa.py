from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import secrets
import os

PADDING_RSA="OAEP"
class RSA:
    
    def _load_public_key(self, clavePublica):
        """Carga una clave pública desde un objeto o archivo PEM."""
        if isinstance(clavePublica, (bytes, str)):
            # Si es ruta a archivo
            if Path(clavePublica).exists():
                with open(clavePublica, "rb") as f:
                    data = f.read()
            else:
                # Si ya es contenido PEM
                data = clavePublica if isinstance(clavePublica, bytes) else clavePublica.encode()
            return serialization.load_pem_public_key(data, backend=default_backend())
        else:
            # Ya es un objeto de clave pública
            return clavePublica

    def _load_private_key(self, clavePrivada):
        """Carga una clave privada desde un objeto o archivo PEM."""
        if isinstance(clavePrivada, (bytes, str)):
            # Si es ruta a archivo
            if Path(clavePrivada).exists():
                with open(clavePrivada, "rb") as f:
                    data = f.read()
            else:
                data = clavePrivada if isinstance(clavePrivada, bytes) else clavePrivada.encode()
            return serialization.load_pem_private_key(data, password=None, backend=default_backend())
        else:
            return clavePrivada

    def _get_padding(self, modeRSA: str):
        """Devuelve el padding correcto según el modo RSA."""
        if modeRSA.upper() == "OAEP":
            return asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        elif modeRSA.upper() == "PKCS1V15":
            return asym_padding.PKCS1v15()
        else:
            raise ValueError("Modo RSA no soportado. Usa 'OAEP' o 'PKCS1v15'.")

    def encriptar_archivo_RSA(self, file_path: str, clavePublica, output_path: str = None):
        """Encripta un archivo con RSA usando la clave pública y el modo indicado."""
        public_key = self._load_public_key(clavePublica)
        padding_mode = self._get_padding(PADDING_RSA)

        file_path = Path(file_path)
        with open(file_path, "rb") as f:
            data = f.read()

        # Encriptamos los datos (limitado por el tamaño de la clave)
        encrypted = public_key.encrypt(data, padding_mode)

        # Si no se indica salida, añadimos ".enc"
        if output_path is None:
            output_path = file_path.with_suffix(file_path.suffix + ".enc")

        with open(output_path, "wb") as f:
            f.write(encrypted)

        print(f"[✔] Archivo encriptado correctamente: {output_path}")

    def desencriptar_archivo_RSA(self, file_path: str, clavePrivada, output_path: str = None):
        """Desencripta un archivo con RSA usando la clave privada y el modo indicado."""
        private_key = self._load_private_key(clavePrivada)
        padding_mode = self._get_padding(PADDING_RSA)

        file_path = Path(file_path)
        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted = private_key.decrypt(encrypted_data, padding_mode)

        # Si no se indica salida, añadimos ".dec"
        if output_path is None:
            output_path = file_path.with_suffix(file_path.suffix + ".dec")

        with open(output_path, "wb") as f:
            f.write(decrypted)

        print(f"[✔] Archivo desencriptado correctamente: {output_path}")

from scapy.all import rdpcap, TCP
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def cargar_clave_privada(ruta_clave):
    with open(ruta_clave, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def ejecutar_seccion_2_2_2(ruta_pcap, ruta_clave):
    clave_privada = cargar_clave_privada(ruta_clave)
    paquetes = rdpcap(ruta_pcap)
    
    for i, pkt in enumerate(paquetes):
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            payload = bytes(pkt[TCP].payload)
            
            if payload.startswith(b"RSA_PIN|"):
                # 1. Extraer los campos según la estructura
                resto_payload = payload[len(b"RSA_PIN|"):]
                
                # La salt ocupa los primeros 16 bytes
                salt = resto_payload[:16]
                pin_cifrado = resto_payload[16:]
                
                print(f"[+] Paquete RSA_PIN encontrado en paquete #{i+1}")
                print(f" -> Salt extraída (hex) : {salt.hex()}")
                print(f" -> Tamaño PIN cifrado  : {len(pin_cifrado)} bytes")
                
                # 2. Descifrar el PIN con la clave privada RSA (OAEP + SHA-256)
                pin_bytes = clave_privada.decrypt(
                    pin_cifrado,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                pin_str = pin_bytes.decode('utf-8')
                print(f" -> PIN recuperado      : {pin_str}")
                
                # 3. Derivar la clave AES de 256 bits (32 bytes) usando Scrypt
                kdf = Scrypt(
                    salt=salt,
                    length=32,       # Clave de 256 bits = 32 bytes
                    n=2**14,          # Costo CPU/memoria = 16384
                    r=8,              # Tamaño de bloque
                    p=1,              # Parámetro de paralelización
                )
                
                clave_aes = kdf.derive(pin_bytes)
                print(f"\n[✓] Clave AES-256 derivada exitosamente:")
                print(f" -> Clave AES (hex)     : {clave_aes.hex()}")
                return clave_aes, salt, pin_str

if __name__ == "__main__":
    ejecutar_seccion_2_2_2("transacciones_cifradas.pcap", "clave_privada.pem")

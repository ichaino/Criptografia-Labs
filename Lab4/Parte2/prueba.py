from scapy.all import rdpcap, TCP
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json

def cargar_clave_privada(ruta_clave):
    with open(ruta_clave, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def ejecutar_descifrado_completo(ruta_pcap, ruta_clave):
    clave_privada = cargar_clave_privada(ruta_clave)
    paquetes = rdpcap(ruta_pcap)
    
    salt = None
    pin_bytes = None
    clave_aes = None
    transacciones = []

    print("==================================================================")
    print(" PASO 1: EXTRAER PIN Y DERIVAR CLAVE AES-256 (Scrypt)")
    print("==================================================================")
    
    for i, pkt in enumerate(paquetes):
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            payload = bytes(pkt[TCP].payload)
            if payload.startswith(b"RSA_PIN|"):
                resto_payload = payload[len(b"RSA_PIN|"):]
                salt = resto_payload[:16]
                pin_cifrado = resto_payload[16:]
                
                # Descifrar PIN
                pin_bytes = clave_privada.decrypt(
                    pin_cifrado,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Derivar clave con Scrypt
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2**14,
                    r=8,
                    p=1,
                )
                clave_aes = kdf.derive(pin_bytes)
                
                print(f"[+] Paquete #{i+1} [RSA_PIN]")
                print(f"    - PIN Recuperado : {pin_bytes.decode('utf-8')}")
                print(f"    - Salt (hex)     : {salt.hex()}")
                print(f"    - Clave AES (hex): {clave_aes.hex()}\n")
                break

    if not clave_aes:
        print("[-] No se pudo obtener la clave AES.")
        return

    print("==================================================================")
    print(" PASO 2: DESCIFRADO DE PAQUETES AES-GCM Y VERIFICACIÓN")
    print("==================================================================")

    aesgcm = AESGCM(clave_aes)
    
    for i, pkt in enumerate(paquetes):
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            payload = bytes(pkt[TCP].payload)
            if payload.startswith(b"AESGCM|"):
                contenido = payload[len(b"AESGCM|"):]
                
                # Extraer Nonce de 12 bytes y el resto (Texto Cifrado + Auth Tag)
                nonce = contenido[:12]
                ciphertext_and_tag = contenido[12:]
                
                try:
                    # Descifrar y autenticar
                    mensaje_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
                    texto_plano = mensaje_bytes.decode('utf-8')
                    
                    print(f"[✓] Paquete #{i+1} [AES-GCM]")
                    print(f"    - Nonce (hex) : {nonce.hex()}")
                    print(f"    - Mensaje     : {texto_plano}")
                    
                    try:
                        transacciones.append(json.loads(texto_plano))
                    except json.JSONDecodeError:
                        transacciones.append(texto_plano)
                        
                except Exception as e:
                    print(f"[-] Error al descifrar el paquete #{i+1}: {e}")

    print("\n==================================================================")
    print(" RESUMEN DE TRANSACCIONES FINAL")
    print("==================================================================")
    for idx, tx in enumerate(transacciones, 1):
        print(f"\n--- Transacción #{idx} ---")
        if isinstance(tx, dict):
            for k, v in tx.items():
                print(f" {k.capitalize():12}: {v}")
        else:
            print(f" Datos: {tx}")

if __name__ == "__main__":
    ejecutar_descifrado_completo("transacciones_cifradas.pcap", "clave_privada.pem")

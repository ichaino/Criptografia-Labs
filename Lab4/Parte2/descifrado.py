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
    transacciones_recuperadas = []

    print("==================================================================")
    print(" PASO 1: EXTRAER PIN Y DERIVAR CLAVE AES-256 (Scrypt)")
    print("==================================================================")
    
    # 1. Buscar el paquete RSA_PIN para recuperar el PIN y la Salt
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
        print("[-] No se pudo obtener la clave AES. Abortando.")
        return

    print("==================================================================")
    print(" PASO 2: DESCIFRADO DE PAQUETES AES-GCM Y VERIFICACIÓN DE INTEGRIDAD")
    print("==================================================================")

    aesgcm = AESGCM(clave_aes)
    
    for i, pkt in enumerate(paquetes):
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            payload = bytes(pkt[TCP].payload)
            if payload.startswith(b"AESGCM|"):
                contenido = payload[len(b"AESGCM|"):]
                
                # Extraer Nonce (12 bytes) y Texto Cifrado + Tag (resto)
                nonce = contenido[:12]
                ciphertext_and_tag = contenido[12:]
                
                try:
                    # AESGCM.decrypt verifica automáticamente el Tag de autenticación
                    mensaje_descifrado = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
                    texto_plano = mensaje_descifrado.decode('utf-8')
                    
                    print(f"[✓] Paquete #{i+1} [AES-GCM - Auténtico]")
                    print(f"    - Nonce (hex) : {nonce.hex()}")
                    print(f"    - Contenido   : {texto_plano}")
                    
                    # Intentar parsear como JSON o estructura si aplica
                    try:
                        datos_tx = json.loads(texto_plano)
                        transacciones_recuperadas.append(datos_tx)
                    except json.JSONDecodeError:
                        transacciones_recuperadas.append(texto_plano)
                        
                except Exception as e:
                    print(f"[-] Paquete #{i+1} [AES-GCM] - Error de autenticación/descifrado: {e}")

    print("\n==================================================================")
    print(" RESUMEN FINAL DE TRANSACCIONES FINANCIERAS RECUPERADAS")
    print("==================================================================")
    for idx, tx in enumerate(transacciones_recuperadas, 1):
        print(f"\n--- Transacción #{idx} ---")
        if isinstance(tx, dict):
            print(f" ID          : {tx.get('id', 'N/A')}")
            print(f" Remitente   : {tx.get('remitente', tx.get('from', 'N/A'))}")
            print(f" Destinatario: {tx.get('destinatario', tx.get('to', 'N/A'))}")
            print(f" Monto       : {tx.get('monto', tx.get('amount', 'N/A'))}")
        else:
            print(f" Datos: {tx}")

if __name__ == "__main__":
    ejecutar_descifrado_completo("transacciones_cifradas.pcap", "clave_privada.pem")

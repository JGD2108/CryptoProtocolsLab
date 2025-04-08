import json
import math
import time
import pyshark
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from Cryptodome.Cipher import ChaCha20
import json
from base64 import b64encode, b64decode

class DiffieHellmanAttacker:
    def __init__(self):
        self.p = None
        self.q = None
        self.g = None
        self.V = None  # Clave pública del servidor
        self.U = None  # Clave pública del cliente
        self.escenario = None
        self.secret = None
        self.salt = None
        self.key = None  # Clave simétrica derivada
        self.encrypted_messages = []

    def load_parameters(self, scenario=None):
        """Carga los parámetros Diffie-Hellman del escenario indicado."""
        try:
            # Si se proporciona un escenario, actualizar el valor
            if scenario is not None:
                self.escenario = scenario
            
            # Verificar que tengamos un escenario antes de continuar
            if self.escenario is None:
                print("Error: No se ha especificado un escenario")
                return False
                
            with open("parameters.json", 'r') as f:
                data = json.load(f)
                params = data["parameters"][self.escenario-1]
                self.p = params["p"]
                self.q = params["q"]
                self.g = params["g"]
                print(f"Parámetros cargados del escenario {self.escenario}:")
                print(f"p = {self.p}")
                print(f"q = {self.q}")
                print(f"g = {self.g}")
                return True
        except Exception as e:
            print(f"Error al cargar parámetros: {e}")
            return False

    def parse_pcap(self, pcap_file):
        """Extrae información del archivo PCAP."""
        try:
            # Cargar el archivo PCAP usando pyshark
            capture = pyshark.FileCapture(pcap_file)
            
            print("Analizando captura de tráfico...")
            for packet in capture:
                # Buscar paquetes TCP con datos
                if 'TCP' in packet and hasattr(packet.tcp, 'payload'):
                    # Convertir la carga útil hexadecimal a texto
                    try:
                        payload = bytes.fromhex(packet.tcp.payload.replace(':', '')).decode('utf-8', errors='ignore')
                        
                        # Buscar información relevante
                        if payload.startswith("MODO:1"):
                            print("PCAP: Modo de comunicación = Diffie-Hellman")
                        
                        elif payload.startswith("ESCENARIO:"):
                            #Despues de los 2 puntos, está el numero del escenario
                            self.escenario = int(payload.split(":")[1].strip())
                            print(self.escenario)
                            self.load_parameters(self.escenario)
                        
                        elif payload.startswith("V:"):
                            self.V = int(payload.split(":")[1].strip())
                            print(f"PCAP: Clave pública del servidor V={self.V}")
                        
                        elif payload.startswith("U:"):
                            self.U = int(payload.split(":")[1].strip())
                            print(f"PCAP: Clave pública del cliente U={self.U}")
                        
                        elif payload.startswith("SAL:"):
                            self.salt = payload.split(":")[1].strip()
                            print(f"PCAP: Salt capturado")
                        
                        # Capturar posibles mensajes cifrados (JSON con nonce y ciphertext)
                        elif "{" in payload and "nonce" in payload and "ciphertext" in payload:
                            print(f"PCAP: Mensaje cifrado capturado: {payload[:50]}...")
                            self.encrypted_messages.append(payload)
                    except Exception as e:
                        # Ignorar errores de decodificación
                        pass
            
            # Si no encontramos todos los valores en el PCAP, usar los proporcionados
            if not self.V:
                print("No se encontró V en PCAP, usando valor proporcionado: 185")
                self.V = 185
            if not self.U:
                print("No se encontró U en PCAP, usando valor proporcionado: 173")
                self.U = 173
            if not self.p:
                print("Cargando parámetros del escenario 1...")
                self.load_parameters(1)
                
            return True
            
        except Exception as e:
            print(f"Error al parsear PCAP: {e}")
            
            # Si falla el parsing, usar los valores proporcionados
            print("Usando valores proporcionados manualmente")
            self.V = 185
            self.U = 173
            self.load_parameters(1)
            return False
        
    def pasosBebe_pasosGigante(self, target_key=None):
        """
        si un atacante puede determinar una de las claves privadas
        (por ejemplo, utilizando el algoritmo de "pasos de bebé, 
        pasos de gigante"), puede calcular el secreto compartido y 
        comprometer la seguridad de la comunicación.
        """
        start_time = time.time()  # Registrar tiempo de inicio
        
        key_to_crack = target_key if target_key is not None else self.U
        
        # Información sobre la clave que estamos intentando crackear
        if key_to_crack == self.V:
            print(f"\nIntentando encontrar la clave privada del servidor (V={key_to_crack})")
        else:
            print(f"\nIntentando encontrar la clave privada del cliente (U={key_to_crack})")
        
        n = self.p-1
        m = math.ceil(n**0.5)
        print(f"Calculando con m = {m}")
        
        # Usar un diccionario en lugar de una lista para búsquedas O(1)
        baby_steps = {}
        
        # Fase 1: Pasos de bebé - Generar la tabla
        print("Generando tabla de pasos bebé...")
        for j in range(m):
            # Verificar tiempo transcurrido
            current_time = time.time()
            elapsed_time = current_time - start_time
            
            if elapsed_time > 3600:
                print("¡TIEMPO EXCEDIDO! El algoritmo ha estado ejecutándose por más de una hora.")
                return None
                
            if j % max(1, min(1000, m//10)) == 0:
                print(f"  Progreso: {j}/{m} ({elapsed_time:.2f} segundos)")
                
            # Guardar directamente en el diccionario para búsqueda O(1)
            baby_steps[pow(self.g, j, self.p)] = j
        
        # Calcular g^(-m) mod p una sola vez
        g_inv = pow(self.g, -1, self.p)
        beta = pow(g_inv, m, self.p)
        
        # Fase 2: Pasos de gigante - Buscar coincidencia
        print("Iniciando búsqueda de pasos gigante...")
        
        # Comenzar con el valor objetivo
        current = key_to_crack
        
        for i in range(m+1):  # +1 para asegurarnos de cubrir todos los casos
            # Verificar tiempo transcurrido
            if i % max(1, min(1000, m//10)) == 0:
                elapsed_time = time.time() - start_time
                print(f"  Progreso: {i}/{m} ({elapsed_time:.2f} segundos)")
                
                if elapsed_time > 3600:
                    print("¡TIEMPO EXCEDIDO! El algoritmo ha estado ejecutándose por más de una hora.")
                    return None
                    
               # Buscar en O(1) usando el diccionario
            if current in baby_steps:
                x = (i * m + baby_steps[current]) % self.q
                elapsed_time = time.time() - start_time
                print(f"¡ÉXITO! Clave privada encontrada en {elapsed_time:.2f} segundos.")
                return x
            
            # Actualizar para la siguiente iteración: current = current * g^(-m) mod p
            current = (current * beta) % self.p
        
        print("No se encontró solución después de m pasos gigante.")
        return None

    def KDF(self, secreto, salt):
        secreto = str(secreto).encode('utf-8')
        salt = b64decode(salt)
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=1,
            lanes=4,
            memory_cost=64 * 1024,
            ad=None,
            secret=None,
        )
        key = kdf.derive(secreto)
        return key
        
    def decipherChacha20(self, key, msg):
        json_input = msg.decode('utf-8')
        try:
            b64 = json.loads(json_input)
            nonce = b64decode(b64['nonce'])
            ciphertext = b64decode(b64['ciphertext'])
            cipher = ChaCha20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
        except (ValueError, KeyError):
            print("Incorrect decryption")

        return plaintext.decode('utf-8')
        
if __name__ == "__main__":
    # Crear instancia del atacante
    attacker = DiffieHellmanAttacker()
    attacker.parse_pcap("escenario1.pcap")
    attacker.load_parameters()
    
    print(f"Datos extraídos: V={attacker.V}, U={attacker.U}, p={attacker.p}, q={attacker.q}, g={attacker.g}")
    
    # Intentar encontrar la clave privada del servidor
    server_private = attacker.pasosBebe_pasosGigante(attacker.V)
    if server_private is not None:
        print(f"Clave privada del servidor encontrada: {server_private}")
        # Calcular el secreto compartido usando la clave privada del servidor
        shared_secret1 = pow(attacker.U, server_private, attacker.p)
        print(f"Secreto compartido calculado (desde servidor): {shared_secret1}")
        key1 = attacker.KDF(shared_secret1, attacker.salt)
        print(f"Clave simétrica 1 derivada")
    else:
        key1 = None
        
    # Intentar encontrar la clave privada del cliente
    client_private = attacker.pasosBebe_pasosGigante(attacker.U)
    if client_private is not None:
        print(f"Clave privada del cliente encontrada: {client_private}")
        # Calcular el secreto compartido usando la clave privada del cliente
        shared_secret2 = pow(attacker.V, client_private, attacker.p)
        print(f"Secreto compartido calculado (desde cliente): {shared_secret2}")
        key2 = attacker.KDF(shared_secret2, attacker.salt)
        print(f"Clave simétrica 2 derivada")
    else:
        key2 = None
    
    # Verificar si ambos secretos son iguales (deberían serlo)
    if server_private is not None and client_private is not None:
        if shared_secret1 == shared_secret2:
            print(f"VERIFICACIÓN EXITOSA: Ambos métodos dieron el mismo secreto compartido: {shared_secret1}")
        else:
            print(f"ALERTA: Los secretos compartidos son diferentes: {shared_secret1} vs {shared_secret2}")
    
    # Decifrar mensajes con ambas claves
    if key1 is not None or key2 is not None:
        print("\n=== Intentando descifrar mensajes ===")
        
        for i, msg in enumerate(attacker.encrypted_messages):
            print(f"\nMensaje cifrado {i+1}:")
            
            if key1 is not None:
                try:
                    plaintext1 = attacker.decipherChacha20(key1, msg.encode('utf-8'))
                    print(f"Con clave 1: {plaintext1}")
                except Exception as e:
                    print(f"Error al descifrar con clave 1: {e}")
            
            if key2 is not None and (key1 != key2):
                try:
                    plaintext2 = attacker.decipherChacha20(key2, msg.encode('utf-8'))
                    print(f"Con clave 2: {plaintext2}")
                except Exception as e:
                    print(f"Error al descifrar con clave 2: {e}")
    else:
        print("No se pudo obtener ninguna clave para descifrar los mensajes")

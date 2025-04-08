# cliente.py - Versión OOP
import socket
import threading
import time
import random
import json
from Cryptodome.Cipher import ChaCha20
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Util.Padding import unpad

class ChatClient:
    def __init__(self, host='localhost', port=8888):
        """Inicializa el cliente de chat."""
        self.host = host
        self.port = port
        self.socket = None
        self.conectado = False
        self.hilo_recepcion = None
        self.hilo_envio = None
        self.p = []
        self.g = []
        self.q = []
        self.escenario_seleccionado = None
        self.modo_comunicacion = None 
        self.secreto_compartido = None
        self.key = None
        self.HEADER = 64
        self.FORMAT = 'utf-8'
    
    def send_bytes(self, data):
        """Enviar bytes sin formatear al servidor."""
        msg_length = len(data)
        send_length = str(msg_length).encode(self.FORMAT)
        send_length += b' ' * (self.HEADER - len(send_length))
        self.socket.send(send_length)
        self.socket.send(data)

    # Modifica el método de envío de mensajes para el escenario 2
    def enviar_mensaje(self, mensaje):
        """Envía un mensaje al servidor."""
        try:
            if self.escenario_seleccionado == 1:
                # Cifrar con ChaCha20
                mensaje_cifrado = self.encypherChacha20(self.key, mensaje)
                self.socket.send(mensaje_cifrado)
            elif self.escenario_seleccionado == 2:
                # Cifrar con AES192
                mensaje_cifrado = self.cipherAES192(self.key, mensaje)
                self.send_bytes(mensaje_cifrado)
            elif self.escenario_seleccionado == 3:
                # Cifrar con ElGamal
                mensaje_cifrado = self.cipherGamal(mensaje)
                self.socket.send(mensaje_cifrado)
            else:
                # Default case - send as plain text
                self.socket.send(mensaje.encode('utf-8'))
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
    
    def conectar(self):
        """Establece conexión con el servidor."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.conectado = True
            print(f"Conectado al servidor en {self.host}:{self.port}")
            
            # Recibir el Escenario del servidor
            modo_msg = self.socket.recv(1024).decode('utf-8')
            if modo_msg.startswith("Escenario:"):
                self.escenario_seleccionado = int(modo_msg.split(":")[1])
                print(f"Usando modo de comunicación {self.escenario_seleccionado}")
            else:
                print(f"Mensaje inesperado del servidor: {modo_msg}")
                self.desconectar()
                return False
                
            return True
        except Exception as e:
            print(f"Error de conexión: {e}")
            return False
    
    def recibir_mensajes(self):
        """Maneja la recepción de mensajes del servidor."""
        while self.conectado:
            try:
                if self.escenario_seleccionado == 1:
                    # Recibir mensaje del servidor usando método tradicional
                    mensaje_cifrado = self.socket.recv(1024)
                    if not mensaje_cifrado:
                        print("Conexión cerrada por el servidor")
                        self.conectado = False
                        break
                    
                    # Descifrar con ChaCha20
                    try:
                        mensaje = self.decipherChacha20(self.key, mensaje_cifrado)
                        if mensaje is None:
                            print("\nError al descifrar mensaje del servidor")
                            continue
                    except Exception as e:
                        print(f"\nError al descifrar: {e}")
                        mensaje = mensaje_cifrado.decode('utf-8', errors='ignore')
                        
                elif self.escenario_seleccionado == 2:
                    # Recibir datos con el protocolo de longitud prefijada
                    msg_length = self.socket.recv(self.HEADER).decode(self.FORMAT)
                    if not msg_length:
                        print("Conexión cerrada por el servidor")
                        self.conectado = False
                        break
                        
                    msg_length = int(msg_length.strip())
                    mensaje_cifrado = self.socket.recv(msg_length)
                    
                    # Decodificar JSON y descifrar con AES192
                    try:
                        mensaje = self.decipherAES192(self.key, mensaje_cifrado)
                        if mensaje is None:
                            print("\nError al descifrar mensaje del servidor")
                            continue
                    except Exception as e:
                        print(f"\nError procesando mensaje: {e}")
                        continue
                elif self.escenario_seleccionado == 3:
                    # Recibir mensaje cifrado con ElGamal
                    mensaje_cifrado = self.socket.recv(1024)
                    if not mensaje_cifrado:
                        print("Conexión cerrada por el servidor")
                        self.conectado = False
                        break
                    
                    # Descifrar con ElGamal
                    try:
                        mensaje = self.decipherGamal(mensaje_cifrado)
                        if mensaje is None:
                            print("\nError al descifrar mensaje del servidor")
                            continue
                    except Exception as e:
                        print(f"\nError al descifrar mensaje ElGamal: {e}")
                        continue
                else:
                    # Fallback para otros escenarios
                    mensaje_cifrado = self.socket.recv(1024)
                    if not mensaje_cifrado:
                        print("Conexión cerrada por el servidor")
                        self.conectado = False
                        break
                    mensaje = mensaje_cifrado.decode('utf-8')
                
                # Borrar la línea actual del prompt (si hay)
                print("\r", end="")
                # Imprimir el mensaje recibido
                print(f"\n>>> Mensaje del servidor: {mensaje}")
                # Reprompt - volver a mostrar el prompt de entrada
                print("Escribe un mensaje (o 'salir' para terminar): ", end="", flush=True)
                    
            except Exception as e:
                print(f"\nError al recibir mensaje: {e}")
                self.conectado = False
                break
                
        print("Conexión con el servidor terminada")
            
    def KDF(self, secreto, salt):
        if isinstance(secreto, tuple):
            secreto = secreto[0]
        secreto = str(secreto).encode('utf-8')
        if self.escenario_seleccionado==1:
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
        elif self.escenario_seleccionado==2:
            kdf = Argon2id(
                salt=salt,
                length=24,
                iterations=1,
                lanes=4,
                memory_cost=64 * 1024,
                ad=None,
                secret=None,
            )
            key = kdf.derive(secreto)
        return key
    
    def enviar_mensajes(self):
        """Maneja el envío de mensajes al servidor."""
        while self.conectado:
            try:
                # Leer mensaje del usuario
                mensaje = input("Escribe un mensaje (o 'salir' para terminar): ")
                
                if mensaje.lower() == 'salir':
                    self.conectado = False
                    break
                
                # Usar el método enviar_mensaje para cifrar y enviar correctamente
                self.enviar_mensaje(mensaje)
                    
            except Exception as e:
                print(f"Error al enviar: {e}")
                self.conectado = False
                break
            
    def encypherChacha20(self, key, msg):
        cipher = ChaCha20.new(key=key)
        plaintext = msg.encode('utf-8')
        ciphertext = cipher.encrypt(plaintext)
        nonce = b64encode(cipher.nonce).decode('utf-8')
        ct = b64encode(ciphertext).decode('utf-8')
        result = json.dumps({'nonce': nonce, 'ciphertext': ct})
        # Se mide hasta después de crear la cadena JSON
        return result.encode('utf-8')
    
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
    
    def cipherAES192(self, key, data):
        # Ensure data is bytes
        if isinstance(data, str):
            data = data.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ciphertext':ct})
        return result.encode('utf-8')

    def decipherAES192(self, key, json_input):
        try:
            b64 = json.loads(json_input)
            iv = b64decode(b64['iv'])
            ct = b64decode(b64['ciphertext'])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            print("The message was: ", pt)
            return pt.decode('utf-8')
        except (ValueError, KeyError):
            print("Incorrect decryption")
    
    def cipherGamal(self, mensaje):
        """Cifra un mensaje usando el esquema ElGamal simplificado."""
        # Convertir mensaje a entero para operaciones modulares
        if isinstance(mensaje, str):
            mensaje_int = int.from_bytes(mensaje.encode('utf-8'), byteorder='big')
        else:
            mensaje_int = int.from_bytes(mensaje, byteorder='big')
            
        # Realizar cifrado: c = m * k mod p
        cipher = (mensaje_int * self.key) % self.p[self.modo]
        return str(cipher).encode('utf-8')
        
    def decipherGamal(self, mensaje_cifrado):
        """Descifra un mensaje usando el esquema ElGamal simplificado."""
        try:
            # Convertir mensaje cifrado a entero
            cipher_int = int(mensaje_cifrado.decode('utf-8'))
            
            # Calcular inverso multiplicativo de la clave
            # k^-1 mod p
            key_inv = pow(self.key, self.p[self.modo]-2, self.p[self.modo])
            
            # Descifrar: m = c * k^-1 mod p
            plaintext_int = (cipher_int * key_inv) % self.p[self.modo]
            
            # Convertir entero a bytes y luego a texto
            # Determinar cuántos bytes necesitamos
            byte_length = (plaintext_int.bit_length() + 7) // 8
            plaintext_bytes = plaintext_int.to_bytes(byte_length, byteorder='big')
            
            # Intentar decodificar como UTF-8, con manejo de errores
            return plaintext_bytes.decode('utf-8', errors='replace')
        except Exception as e:
            print(f"Error decifrando mensaje: {e}")
            return None
    
    def iniciar_hilos(self):
        """Inicia los hilos de envío y recepción."""
        # Crear los dos hilos
        self.hilo_recepcion = threading.Thread(target=self.recibir_mensajes)
        self.hilo_envio = threading.Thread(target=self.enviar_mensajes)
        
        # Configurar como daemon (terminan cuando el programa principal termina)
        self.hilo_recepcion.daemon = True
        
        # Iniciar los hilos
        self.hilo_recepcion.start()
        self.hilo_envio.start()
    
    def esperar_finalizacion(self):
        """Espera a que finalice el hilo de envío."""
        if self.hilo_envio:
            self.hilo_envio.join()
    
    def desconectar(self):
        """Cierra la conexión con el servidor."""
        if self.socket:
            try:
                self.socket.close()
                print("Conexión cerrada")
            except:
                pass  # Ignorar errores al cerrar el socket
    
    def iniciar(self):
        """Método principal para iniciar el cliente."""
        # Primero cargar parámetros (en caso de ser necesarios para DH)
        self.cargar_parametros_diffie_hellman()
        
        # Luego conectar y recibir el modo de comunicación
        if self.conectar():
            # Manejar según el modo de comunicación
            if self.escenario_seleccionado == 1:
                # Modo 1: Diffie-Hellman
                if self.realizar_intercambio_diffie_hellman():
                    print(f"Intercambio Diffie-Hellman completado. Secreto compartido: {self.secreto_compartido}")
                    # recibir salt del servidor 
                    salt_msg = self.socket.recv(1024).decode('utf-8')
                    if salt_msg.startswith("SAL:"):
                        salt_b64 = salt_msg.split(":")[1]
                        salt = b64decode(salt_b64)
                        print("Salt recibido del servidor")
                        self.key = self.KDF(self.secreto_compartido, salt)
                    else:
                        print(f"Error: mensaje inesperado en lugar de salt: {salt_msg}")
                    
                    # Solo después de DH exitoso, iniciar hilos de chat
                    self.iniciar_hilos()
                    self.esperar_finalizacion()
                else:
                    print("Fallo en el intercambio Diffie-Hellman. Terminando.")
                    self.desconectar()
            
            elif self.escenario_seleccionado == 2:
                if self.realizar_intercambio_diffie_hellman():
                    print(self.secreto_compartido)
                    print(f"Intercambio Diffie-Hellman completado. Secreto compartido: {self.secreto_compartido}")
                    # recibir salt del servidor 
                    salt_msg = self.socket.recv(1024).decode('utf-8')
                    if salt_msg.startswith("SAL:"):
                        salt_b64 = salt_msg.split(":")[1]
                        salt = b64decode(salt_b64)
                        print("Salt recibido del servidor")
                        self.key = self.KDF(self.secreto_compartido, salt)
                    else:
                        print(f"Error: mensaje inesperado en lugar de salt: {salt_msg}")
                    
                    # Solo después de DH exitoso, iniciar hilos de chat
                    self.iniciar_hilos()
                    self.esperar_finalizacion()
            
            # In the iniciar method, update the section for scenario 3:
            elif self.escenario_seleccionado == 3:
                if self.realizar_intercambio_diffie_hellman():
                    print(f"Intercambio ElGamal completado. Secreto compartido: {self.secreto_compartido}")
                    # La clave para ElGamal ya está establecida en self.key
                    self.key = self.secreto_compartido
                    print("Clave ElGamal establecida correctamente")
                    
                    # Iniciar hilos de chat
                    self.iniciar_hilos()
                    self.esperar_finalizacion()
                else:
                    print("Fallo en el intercambio de claves ElGamal. Terminando.")
                    self.desconectar()
        else:
            print(f"Modo de comunicación desconocido: {self.modo_comunicacion}")
            self.desconectar()

    
    def leer_parametros_json(self, ruta_archivo="parameters.json"):
        """Lee y retorna los parámetros desde el archivo JSON."""
        try:
            with open(ruta_archivo, 'r') as archivo:
                datos = json.load(archivo)
                return datos["parameters"]  # Accede a la lista de parámetros
        except FileNotFoundError:
            print(f"Error: No se encontró el archivo {ruta_archivo}")
            return None
        except json.JSONDecodeError:
            print(f"Error: El archivo {ruta_archivo} no contiene JSON válido")
            return None
        except Exception as e:
            print(f"Error al leer el archivo: {e}")
            return None
    
    def cargar_parametros_diffie_hellman(self):
        """Carga los parámetros para Diffie-Hellman."""
        parametros = self.leer_parametros_json()
        if parametros:
            # Limpiar listas para evitar duplicados
            self.p.clear()
            self.q.clear()
            self.g.clear()
            
            for i in range(len(parametros)):
                self.p.append(parametros[i]["p"])
                self.q.append(parametros[i]["q"])
                self.g.append(parametros[i]["g"])
            
            print(f"Se cargaron {len(self.p)} conjuntos de parámetros")
            return True
        else:
            print("No se pudieron cargar los parámetros")
            return False
    
    def realizar_intercambio_diffie_hellman(self):
        """Realiza el intercambio de claves Diffie-Hellman con el servidor, por turnos."""
        if self.escenario_seleccionado == 1:
            try:
                # 1. Recibir el escenario seleccionado por el servidor
                mensaje_escenario = self.socket.recv(1024).decode('utf-8')
                
                if mensaje_escenario.startswith("Modo:"):
                    self.modo = int(mensaje_escenario.split(":")[1])
                    print(f"Usando parámetros del escenario {self.modo+1} seleccionado por el servidor")
                    print(f"p = {self.p[self.modo]}")
                    print(f"q = {self.q[self.modo]}")
                    print(f"g = {self.g[self.modo]}")
                else:
                    print(f"Respuesta inesperada del servidor: {mensaje_escenario}")
                    return False
                
                # 2. Recibir la clave pública U del servidor
                mensaje_u = self.socket.recv(1024).decode('utf-8')
                
                if mensaje_u.startswith("U:"):
                    U = int(mensaje_u.split(":")[1].strip())
                    print(f"Recibida clave pública U={U} del servidor")
                else:
                    print(f"Respuesta inesperada del servidor: {mensaje_u}")
                    return False
                
                # 3. Generar clave privada
                p = self.p[self.modo]
                q = self.q[self.modo]
                g = self.g[self.modo]
                b = random.randint(2, q - 1)
                
                # 4. Calcular y enviar clave pública
                V = pow(g, b, p)
                self.socket.send(f"V:{V}".encode('utf-8'))
                print(f"Enviada clave pública V={V} al servidor")
                
                # 5. Calcular secreto compartido
                secreto = pow(U, b, p)
                self.secreto_compartido = secreto
                
                # 6. Recibir confirmación
                confirmacion = self.socket.recv(1024).decode('utf-8')
                print(f"Confirmación del servidor: {confirmacion}")
                
                if confirmacion.startswith("DH-OK:"):
                    
                    return True
                else:
                    print("No se recibió confirmación adecuada")
                    return False
                    
            except Exception as e:
                print(f"Error en intercambio Diffie-Hellman: {e}")
                return False
        elif self.escenario_seleccionado == 2:
            try:
                p = 2**256 - 2**224 + 2**192 + 2**96 - 1
                q = 2**256 - 2**224 + 2**192 - 89188191075325690597107910205041859247
                a = -3
                b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
                x = 48439561293906451759052585252797914202762949526041747995844080717082404635286
                y = 36134250956749795798585127919587881956611106672985015071877198253568414405109
                G = (x, y)
                
                if self.is_point_on_curve(x, y, a, b, p):
                    print("✅El punto G pertenece a la curva P-256.")
                else:
                    print("❌El punto G NO pertenece a la curva P-256.")
                    return False
                    
                beta = random.randint(2, q - 1)  
                V = scalar_multiply(beta, G, a, p) 
                
                mensaje_servidor = self.socket.recv(1024).decode('utf-8')
                if mensaje_servidor.startswith("U:"):
                    # Extract the point as a string and convert to tuple
                    U_str = mensaje_servidor.split(":")[1].strip()
                    U = eval(U_str)  # Convert string representation to tuple
                    print(f"Recibida clave pública U={U} del servidor")
                    
                    # Calculate shared secret
                    self.secreto_compartido = scalar_multiply(beta, U, a, p)
                    print(f"Calculado secreto compartido: {self.secreto_compartido}")
                    
                    # Send our public key
                    self.socket.send(f"V:{V}".encode('utf-8'))
                    print(f"Enviada clave pública V={V} al servidor")
                    
                    # Wait for confirmation
                    confirmacion = self.socket.recv(1024).decode('utf-8')
                    if confirmacion.startswith("DH-OK:"):
                        return True
                    else:
                        print(f"Confirmación incorrecta: {confirmacion}")
                        return False
                else:
                    print(f"Mensaje inesperado del servidor: {mensaje_servidor}")
                    return False
            except Exception as e:
                print(f"Error en intercambio ECDH: {e}")
                return False
        elif self.escenario_seleccionado == 3:
            try:
                # Receive setup message from server
                mensaje_inicial = self.socket.recv(1024).decode('utf-8')
                print(f"DEBUG: Received raw message: '{mensaje_inicial}'")
                
                # Check if we received merged messages (Modo:X and U:Y combined)
                if "Modo:" in mensaje_inicial and "U:" in mensaje_inicial:
                    print("Detected merged messages, splitting them...")
                    
                    # Extract mode
                    modo_str = mensaje_inicial.split("Modo:")[1].split("U:")[0].strip()
                    self.modo = int(modo_str)
                    print(f"Extracted mode: {self.modo}")
                    
                    # Extract U value
                    U_str = mensaje_inicial.split("U:")[1].strip()
                    U = int(U_str)
                    print(f"Extracted server public key U={U}")
                else:
                    # Handle standard separate messages
                    if mensaje_inicial.startswith("Modo:"):
                        self.modo = int(mensaje_inicial.split(":")[1])
                        print(f"Using parameters from set {self.modo+1}")
                        print(f"p = {self.p[self.modo]}")
                        print(f"q = {self.q[self.modo]}")
                        print(f"g = {self.g[self.modo]}")
                        
                        # Receive U separately
                        mensaje_u = self.socket.recv(1024).decode('utf-8')
                        if mensaje_u.startswith("U:"):
                            U = int(mensaje_u.split(":")[1].strip())
                            print(f"Received public key U={U} from server")
                        else:
                            print(f"Unexpected message format: {mensaje_u}")
                            return False
                    else:
                        print(f"Unexpected message format: {mensaje_inicial}")
                        return False
                
                # Continue with ElGamal - generate our key pair
                p = self.p[self.modo]
                q = self.q[self.modo]
                g = self.g[self.modo]
                b = random.randint(2, q - 1)
                
                # Calculate and send public key
                V = pow(g, b, p)
                self.socket.send(f"V:{V}".encode('utf-8'))
                print(f"Sent public key V={V} to server")
                
                # Calculate shared secret
                secreto = pow(U, b, p)
                self.secreto_compartido = secreto
                
                # Receive confirmation
                confirmacion = self.socket.recv(1024).decode('utf-8')
                print(f"Confirmation from server: {confirmacion}")
                
                if confirmacion.startswith("DH-OK:"):
                    return True
                else:
                    print("Did not receive proper confirmation")
                    return False
            except Exception as e:
                print(f"Error in ElGamal key exchange: {e}")
                import traceback
                traceback.print_exc()
                return False
               
    def is_point_on_curve(self, x, y, a, b, p):
        """Verifica si un punto (x,y) pertenece a la curva elíptica y² = x³ + ax + b (mod p)"""
        return (y**2 - (x**3 + a*x + b)) % p == 0
    
def point_addition(P, Q, a_curve, p):
    """Add two points on an elliptic curve"""
    if P is None: return Q
    if Q is None: return P
    
    x1, y1 = P
    x2, y2 = Q
    
    # If points are the same, use point doubling
    if x1 == x2 and y1 == y2:
        return point_doubling(P, a_curve, p)
    
    # If points are inverses, return infinity
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    
    # Calculate slope
    x_diff = (x2 - x1) % p
    x_diff_inv = pow(x_diff, p - 2, p)  # Modular inverse
    slope = ((y2 - y1) * x_diff_inv) % p
    
    # Calculate new point
    x3 = (slope**2 - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    
    return (x3, y3)

def point_doubling(P, a_curve, p):
    """Double a point on an elliptic curve"""
    if P is None: return None
    
    x, y = P
    if y == 0: return None
    
    # Calculate slope of tangent line
    numerator = (3 * x**2 + a_curve) % p
    denominator = (2 * y) % p
    denominator_inv = pow(denominator, p - 2, p)
    slope = (numerator * denominator_inv) % p
    
    # Calculate new point
    x3 = (slope**2 - 2*x) % p
    y3 = (slope * (x - x3) - y) % p
    
    return (x3, y3)

def scalar_multiply(alpha, P, a_curve, p):
    """Multiply point P by scalar k using double-and-add algorithm"""
    result = None  # Point at infinity
    addend = P
    
    while alpha > 0:
        if alpha & 1:  # If bit is set
            result = point_addition(result, addend, a_curve, p)
        addend = point_doubling(addend, a_curve, p)
        alpha >>= 1
    
    return result

if __name__ == "__main__": 
    cliente = ChatClient()
    try:
        cliente.iniciar()
    except KeyboardInterrupt:
        print("\nCliente detenido por el usuario")
    finally:
        cliente.desconectar()
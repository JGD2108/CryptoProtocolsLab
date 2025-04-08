# servidor_oop.py
import socket
import threading
import random
import json
import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from Cryptodome.Cipher import ChaCha20
import json
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Util.Padding import unpad



class ChatServer:
    def __init__(self,host="localhost", port=8888):
        """Inicializa el servidor de chat."""
        self.host = host
        self.port = port
        self.socket = None
        self.clientes = []  # Lista para guardar los clientes conectados
        self.activo = False
        self.hilo_envio = None
        self.hilo_aceptacion = None
        self.p = list()
        self.q = list()
        self.g = list()
        self.escenario_seleccionado = None  # 1: Diffie-Hellman, 2 y 3: otros modos
        self.modo_comunicacion = None  # Parámetros Diffie Hellman
        self.secreto_compartido = None
        self.key = None  # Clave simétrica para cifrado
        self.HEADER = 64
        self.FORMAT = 'utf-8'
   
    def recv_bytes(self, cliente_socket):
        """Recibe bytes con formato de longitud desde un cliente."""
        try:
            msg_length = cliente_socket.recv(self.HEADER).decode(self.FORMAT)
            if not msg_length:
                return None
               
            msg_length = int(msg_length.strip())
            data = cliente_socket.recv(msg_length)
            return data
        except Exception as e:
            print(f"Error recibiendo bytes: {e}")
            return None

    # Modifica el método de recepción para el escenario 2
    def recibir_mensajes(self, cliente_socket, direccion):
        """Maneja la recepción de mensajes de un cliente específico."""
        while self.activo:
            try:
                if self.escenario_seleccionado == 1:
                    # Recibir mensaje del cliente usando método tradicional
                    mensaje = cliente_socket.recv(1024)
                    if not mensaje:
                        break
                    mensaje = self.decipherChacha20(self.key, mensaje)
                elif self.escenario_seleccionado == 2:
                    # Usar el protocolo de longitud prefijada para AES
                    mensaje_cifrado = self.recv_bytes(cliente_socket)
                    if not mensaje_cifrado:
                        break
                   
                    # Decodificar JSON y descifrar
                    try:
                        mensaje = self.decipherAES192(self.key, mensaje_cifrado)
                        if mensaje is None:
                            print(f"Error al descifrar mensaje de {direccion}")
                            continue
                    except Exception as e:
                        print(f"Error procesando mensaje de {direccion}: {e}")
                        continue
                elif self.escenario_seleccionado == 3:
                    mensaje_cifrado = cliente_socket.recv(1024)
                    if not mensaje_cifrado:
                        break
                    try:
                        mensaje = self.decipherGamal(mensaje_cifrado)
                        if mensaje is None:
                            print(f"Error al descifrar mensaje de {direccion}")
                            continue
                    except Exception as e:
                        print(f"Error procesando mensaje de {direccion}: {e}")
                        continue
                    
                print(f"Mensaje recibido de {direccion}: {mensaje}")
               
            except Exception as e:
                print(f"Error con cliente {direccion}: {e}")
                break
       
        # Cerrar conexión cuando hay error o el cliente se desconecta
        self.desconectar_cliente(cliente_socket)
        print(f"Cliente {direccion} desconectado")
    
    
    def inicializar_socket(self):
        """Configura el socket del servidor."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Servidor iniciado en {self.host}:{self.port}")
   
    def enviar_mensajes(self):
        """Envía mensajes del administrador a todos los clientes conectados."""
        while self.activo:
            try:
                # Esperar entrada del administrador del servidor
                mensaje = input("Mensaje para enviar a todos los clientes (o 'salir' para terminar): ")
               
                if mensaje.lower() == 'salir':
                    self.activo = False
                    break
               
                # Enviar el mensaje a todos los clientes conectados
                self.broadcast(f"SERVIDOR: {mensaje}")
                   
            except Exception as e:
                print(f"Error en el hilo de envío: {e}")
   
    def broadcast(self, mensaje):
        """Envía un mensaje a todos los clientes conectados."""
        for cliente in self.clientes[:]:  
            try:
                if self.escenario_seleccionado == 1:
                    mensaje_cifrado = self.encypherChacha20(self.key, mensaje)
                    cliente.send(mensaje_cifrado)
                elif self.escenario_seleccionado == 2:
                    mensaje_cifrado = self.cipherAES192(self.key, mensaje)
                    # Enviar usando el formato de longitud
                    msg_length = len(mensaje_cifrado)
                    send_length = str(msg_length).encode(self.FORMAT)
                    send_length += b' ' * (self.HEADER - len(send_length))
                    cliente.send(send_length)
                    cliente.send(mensaje_cifrado)
                else:
                    mensaje_cifrado = self.cipherGamal(mensaje)
                    cliente.send(mensaje_cifrado)
            except:
                self.desconectar_cliente(cliente)
   
    def desconectar_cliente(self, cliente_socket):
        """Desconecta un cliente y limpia sus recursos."""
        if cliente_socket in self.clientes:
            self.clientes.remove(cliente_socket)
        try:
            cliente_socket.close()
        except:
            pass  # Ignorar errores al cerrar el socket
   
    def KDF(self, secreto, salt):
        # Si el secreto es una tupla (escenario 2), usar solo la coordenada x
        if isinstance(secreto, tuple):
            secreto = secreto[0]  # Usar solo la coordenada x del punto
       
        # Convertir a string y luego a bytes
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
        # Make sure data is properly encoded
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data
           
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))
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
            return pt.decode('utf-8')  # Return the decoded message
        except (ValueError, KeyError):
            print("Incorrect decryption")
            return None
   
    def aceptar_conexiones(self):
        """Acepta nuevas conexiones de clientes."""
        try:
            while self.activo:
                try:
                    # Configurar timeout para poder verificar la bandera activo
                    self.socket.settimeout(1.0)  # 1 segundo de timeout
                    cliente_socket, direccion = self.socket.accept()
                    print(f"Nueva conexión de {direccion}")
                   
                    # Enviar el escenario seleccionado al cliente
                    cliente_socket.send(f"Escenario:{self.escenario_seleccionado}".encode('utf-8'))
                    print(f"Enviado modo de comunicación {self.escenario_seleccionado} al cliente")
                   
                    # Manejar según el modo de comunicación seleccionado
                    if self.escenario_seleccionado == 1:
                        # Modo 1: Diffie-Hellman
                        secreto = self.realizar_intercambio_diffie_hellman(cliente_socket, direccion)
                        if secreto:
                            print(f"Intercambio Diffie-Hellman completado con {direccion}. Secreto: {secreto}")
                            salt = os.urandom(16)
                            salt_b64 = b64encode(salt).decode('utf-8')
                            cliente_socket.send(f"SAL:{salt_b64}".encode('utf-8'))
                            symetric_key = self.KDF(secreto, salt)
                            self.key = symetric_key
                            self.clientes.append(cliente_socket)  # Agregar cliente a la lista
                            # Crear un hilo para la recepción continua
                            hilo_cliente = threading.Thread(
                                target=self.recibir_mensajes,
                                args=(cliente_socket, direccion)
                            )
                            hilo_cliente.daemon = True
                            hilo_cliente.start()
                        else:
                            print(f"Fallo en intercambio Diffie-Hellman con {direccion}")
                            cliente_socket.close()
                           
                    elif self.escenario_seleccionado == 2:
                        secreto = self.realizar_intercambio_diffie_hellman(cliente_socket, direccion)
                        if secreto:
                            print(f"Intercambio Diffie-Hellman completado con {direccion}. Secreto: {secreto}")
                            salt = os.urandom(16)
                            salt_b64 = b64encode(salt).decode('utf-8')
                            cliente_socket.send(f"SAL:{salt_b64}".encode('utf-8'))
                            symetric_key = self.KDF(secreto, salt)
                            self.key = symetric_key
                            self.clientes.append(cliente_socket)  # Agregar cliente a la lista
                            # Crear un hilo para la recepción continua
                            hilo_cliente = threading.Thread(
                                target=self.recibir_mensajes,
                                args=(cliente_socket, direccion)
                            )
                            hilo_cliente.daemon = True
                            hilo_cliente.start()                       
                    elif self.escenario_seleccionado == 3:
                        secreto = self.realizar_intercambio_diffie_hellman(cliente_socket, direccion) 
                        if secreto:
                            self.clientes.append(cliente_socket)  # Agregar cliente a la lista
                            hilo_cliente = threading.Thread(
                                target=self.recibir_mensajes,   
                                args=(cliente_socket, direccion)
                                )
                            hilo_cliente.daemon = True
                            hilo_cliente.start()
                    else:
                        print(f"Modo de comunicación desconocido: {self.modo_comunicacion}")
                        cliente_socket.send("ERROR:Modo de comunicación no válido".encode('utf-8'))
                        cliente_socket.close()
                   
                except socket.timeout:
                    # Timeout al aceptar, verificamos la bandera y continuamos
                    continue
                   
        except Exception as e:
            print(f"Error en el hilo de aceptación: {e}")
       
        print("Cerrando el servidor...")
   
    def iniciar(self):
        """Inicia el servidor y todos sus hilos."""
        try:
            # Primero cargar parámetros
            self.cargar_parametros_diffie_hellman()
           
            # Seleccionar modo de comunicación
            try:
                self.escenario_seleccionado = int(input("Ingrese el Escenario (Escenario 1: Diffie-Hellman, Escenario 2: Modo 2, Escenario 3: Modo 3): "))
                if 1 <= self.escenario_seleccionado <= 3:
                    print(f"Usando Escenario {self.escenario_seleccionado}")
                   
                    # Si es Diffie-Hellman, también seleccionar escenario
                    if self.escenario_seleccionado == 1 or self.escenario_seleccionado == 3:
                        self.seleccionar_combinación_diffie_hellman()
                                    # Inicializar socket y activar servidor
                    self.inicializar_socket()
                    self.activo = True
                    # Crear e iniciar el hilo para aceptar conexiones
                    self.hilo_aceptacion = threading.Thread(target=self.aceptar_conexiones)
                    self.hilo_aceptacion.daemon = True
                    self.hilo_aceptacion.start()
                   
                        # Crear e iniciar el hilo para enviar mensajes
                    self.hilo_envio = threading.Thread(target=self.enviar_mensajes)
                    self.hilo_envio.daemon = True
                    self.hilo_envio.start()
                   
                    # Mantener el hilo principal vivo hasta que termine el hilo de envío
                    self.hilo_envio.join()
               
                else:
                    print("Número fuera de rango. Usando modo 1 (Diffie-Hellman) por defecto.")
            except ValueError:
                print("Entrada inválida. Usando modo 1 (Diffie-Hellman) por defecto.")
        except KeyboardInterrupt:
            print("Servidor detenido")
            self.activo = False
        finally:
            self.detener()
   
    def seleccionar_combinación_diffie_hellman(self):
        """Selecciona el escenario para Diffie-Hellman."""
        try:
            num = int(input("Ingrese la combinación de parametros que desea Diffie-Hellman (1 a 5): "))
            if 1 <= num <= 5:
                self.modo= num - 1
                print(f"Usando escenario {num}:")
                print(f"p = {self.p[self.modo]}")
                print(f"q = {self.q[self.modo]}")
                print(f"g = {self.g[self.modo]}")
            else:
                print("Número fuera de rango. Usando escenario 1 por defecto.")
                self.modo = 0
        except ValueError:
            print("Entrada inválida. Usando escenario 1 por defecto.")
            self.modo = 0
   
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
    def cipherGamal(self, mensaje):
        """Cifra un mensaje usando el esquema ElGamal simplificado."""
        # Convertir mensaje a entero para operaciones modulares
        if isinstance(mensaje, str):
            mensaje_int = int.from_bytes(mensaje.encode('utf-8'), byteorder='big')
        else:
            mensaje_int = int.from_bytes(mensaje, byteorder='big')
            
        # Usar el módulo p correcto para el modo actual
        p = self.p[self.modo]
        
        # Realizar cifrado: c = m * k mod p
        cipher = (mensaje_int * self.key) % p
        return str(cipher).encode('utf-8')

    def decipherGamal(self, mensaje_cifrado):
        """Descifra un mensaje usando el esquema ElGamal simplificado."""
        try:
            # Convertir mensaje cifrado a entero
            cipher_int = int(mensaje_cifrado.decode('utf-8'))
            
            # Usar el módulo p correcto para el modo actual
            p = self.p[self.modo]
            
            # Calcular inverso multiplicativo de la clave
            key_inv = pow(self.key, p-2, p)
            
            # Descifrar: m = c * k^-1 mod p
            plaintext_int = (cipher_int * key_inv) % p
            
            # Convertir entero a bytes y luego a texto
            # Determinar cuántos bytes necesitamos
            byte_length = (plaintext_int.bit_length() + 7) // 8
            plaintext_bytes = plaintext_int.to_bytes(byte_length, byteorder='big')
            
            # Intentar decodificar como UTF-8, con manejo de errores
            return plaintext_bytes.decode('utf-8', errors='replace')
        except Exception as e:
            print(f"Error decifrando mensaje ElGamal: {e}")
            return None
    
    
    def realizar_intercambio_diffie_hellman(self, cliente_socket, direccion):
        """Realiza el intercambio de claves Diffie-Hellman con un cliente, por turnos."""
        if self.escenario_seleccionado == 1:
            try:
                # Usar los parámetros del escenario seleccionado
                p = self.p[self.modo]
                q = self.q[self.modo]
                g = self.g[self.modo]
               
                # 1. Enviar al cliente el escenario seleccionado
                cliente_socket.send(f"Modo:{self.modo}".encode('utf-8'))
                print(f"Enviado modo {self.modo} al cliente")
               
                # 2. Generar clave privada del servidor
                a = random.randint(2, q - 1) #generar alpha
               
                # 3. Calcular y enviar clave pública del servidor
                U = pow(g, a, p)
                cliente_socket.send(f"U:{U}".encode('utf-8'))
                print(f"Enviada clave pública U={U} al cliente")
               
                # 4. Recibir clave pública del cliente
                mensaje_cliente = cliente_socket.recv(1024).decode('utf-8')
               
                # 5. Procesar respuesta del cliente
                if mensaje_cliente.startswith("V:"):
                    V = int(mensaje_cliente.split(":")[1].strip())
                    print(f"Recibida clave pública V={V} del cliente")
                   
                    # 6. Calcular el secreto compartido
                    secreto = pow(V, a, p)
                    print(f"Calculado secreto compartido: {secreto}")
                   
                    # 7. Enviar confirmación
                    cliente_socket.send("DH-OK:Intercambio completado".encode('utf-8'))
                   
                    # Guardar el secreto para este cliente
                    self.secreto_compartido = secreto
                    return secreto
                else:
                    print(f"Respuesta inesperada del cliente: {mensaje_cliente}")
                    return None        
            except Exception as e:
                print(f"Error en intercambio Diffie-Hellman con {direccion}: {e}")
                return
           

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
                    return
                alpha = random.randint(2, q - 1)  
                U = scalar_multiply(alpha, G, a, p)
                cliente_socket.send(f"U:{U}".encode('utf-8'))
                print(f"Enviada clave pública U={U} al cliente")
               
                # 4. Recibir clave pública del cliente
                mensaje_cliente = cliente_socket.recv(1024).decode('utf-8')
               
                # 5. Procesar respuesta del cliente
                if mensaje_cliente.startswith("V:"):
                    # Parse the point as a tuple using eval
                    V_str = mensaje_cliente.split(":")[1].strip()
                    V = eval(V_str)  # Convert string representation to tuple
                    print(f"Recibida clave pública V={V} del cliente")
                    secreto = scalar_multiply(alpha, V, a, p)
                    print(f"Calculado secreto compartido: {secreto}")
                   
                    # 7. Enviar confirmación
                    cliente_socket.send("DH-OK:Intercambio completado".encode('utf-8'))
                   
                    # Guardar el secreto para este cliente
                    self.secreto_compartido = secreto
                    return secreto
               
            except Exception as e:
                print(f"Error en escenario 2: {e}")
                return None
        elif self.escenario_seleccionado == 3:
            try:
                # Use indexed parameters just like scenario 1
                p = self.p[self.modo]
                q = self.q[self.modo]
                g = self.g[self.modo]
                
                # 1. Send mode to client
                cliente_socket.send(f"Modo:{self.modo}".encode('utf-8'))
                print(f"Enviado modo {self.modo} al cliente")
                
                # 2. Generate private key and public key
                alpha = random.randint(2, q - 1)  # Clave privada
                U = pow(g, alpha, p)
                
                # 3. Send public key to client
                cliente_socket.send(f"U:{U}".encode('utf-8'))
                print(f"Enviada clave pública U={U} al cliente")
                
                # 4. Receive client's public key
                mensaje_cliente = cliente_socket.recv(1024).decode('utf-8')
                
                # 5. Process client response
                if mensaje_cliente.startswith("V:"):
                    V = int(mensaje_cliente.split(":")[1].strip())
                    print(f"Recibida clave pública V={V} del cliente")
                    
                    # 6. Calculate shared secret
                    secreto = pow(V, alpha, p)
                    print(f"Calculado secreto compartido: {secreto}")
                    
                    # 7. Send confirmation
                    cliente_socket.send("DH-OK:Intercambio completado".encode('utf-8'))
                    
                    # Save the secret for this client
                    self.secreto_compartido = secreto
                    self.key = secreto  # Use directly as key for ElGamal
                    return secreto
                else:
                    print(f"Respuesta inesperada del cliente: {mensaje_cliente}")
                    return None
            except Exception as e:
                print(f"Error en intercambio ElGamal con {direccion}: {e}")
                return None
            
            
   
    def is_point_on_curve(self, x, y, a, b, p):
        """Verifica si un punto (x,y) pertenece a la curva elíptica y² = x³ + ax + b (mod p)"""
        return (y**2 - (x**3 + a*x + b)) % p == 0

   
    def detener(self):
        """Detiene el servidor y limpia todos los recursos."""
        self.activo = False
       
        # Cerrar todas las conexiones
        for cliente in self.clientes[:]:
            self.desconectar_cliente(cliente)
           
        if self.socket:
            self.socket.close()
           
        print("Servidor cerrado")

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



# Bloque principal
if __name__ == "__main__":
    servidor = ChatServer()
    try:
        servidor.iniciar()
    except KeyboardInterrupt:
        print("\nServidor detenido por el usuario")
    finally:
        servidor.detener()
# cliente.py - Versión OOP
import socket
import threading
import time
import random
import json
from Cryptodome.Cipher import ChaCha20
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

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
        self.escenario_seleccionado = 0
        self.modo_comunicacion = 1  # Por defecto Diffie-Hellman
        self.secreto_compartido = None
        self.key = None
    
    def conectar(self):
        """Establece conexión con el servidor."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.conectado = True
            print(f"Conectado al servidor en {self.host}:{self.port}")
            
            # Recibir el modo de comunicación del servidor
            modo_msg = self.socket.recv(1024).decode('utf-8')
            if modo_msg.startswith("MODO:"):
                self.modo_comunicacion = int(modo_msg.split(":")[1])
                print(f"Usando modo de comunicación {self.modo_comunicacion}")
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
                # Recibir mensaje del servidor
                mensaje = self.socket.recv(1024)
                if not mensaje:
                    print("Conexión cerrada por el servidor")
                    self.conectado = False
                    break
                
                if self.modo_comunicacion==1:
                    try:
                        mensaje = self.decipherChacha20(self.key, mensaje)
                    except Exception as e:
                        print(f"\nError al descifrar: {e}")
                        mensaje = mensaje.decode('utf-8', errors='ignore')
                else:
                    mensaje = mensaje.decode('utf-8')
                
                # Borrar la línea actual del prompt (si hay)
                print("\r", end="")
                # Imprimir el mensaje recibido
                print(f"\n>>> Mensaje del servidor: {mensaje}")
                # Reprompt - volver a mostrar el prompt de entrada
                print("Escribe un mensaje (o 'salir' para terminar): ", end="", flush=True)
                
            except Exception as e:
                print(f"\nError al recibir: {e}")
                self.conectado = False
                break
            
    def KDF(self, secreto, salt):
        secreto = str(secreto).encode('utf-8')
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
    
    def enviar_mensajes(self):
        """Maneja el envío de mensajes al servidor."""
        while self.conectado:
            try:
                # Leer mensaje del usuario
                mensaje = input("Escribe un mensaje (o 'salir' para terminar): ")
                
                if mensaje.lower() == 'salir':
                    self.conectado = False
                    break
                if self.modo_comunicacion==1:
                    mensaje = self.encypherChacha20(self.key, mensaje)

                self.socket.send(mensaje)
                
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
            if self.modo_comunicacion == 1:
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
            
            elif self.modo_comunicacion == 2:
                # Modo 2: Placeholder para otro protocolo
                print("Usando modo de comunicación 2")
                self.manejar_modo_comunicacion_2()
            
            elif self.modo_comunicacion == 3:
                # Modo 3: Placeholder para otro protocolo
                print("Usando modo de comunicación 3")
                self.manejar_modo_comunicacion_3()
            
            else:
                print(f"Modo de comunicación desconocido: {self.modo_comunicacion}")
                self.desconectar()
    
    def manejar_modo_comunicacion_2(self):
        """Maneja el segundo modo de comunicación (placeholder)."""
        pass  # Implementar el segundo modo de comunicación aquí
    
    def manejar_modo_comunicacion_3(self):
        """Maneja el tercer modo de comunicación (placeholder)."""
        pass  # Implementar el tercer modo de comunicación aquí
    
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
        try:
            # 1. Recibir el escenario seleccionado por el servidor
            mensaje_escenario = self.socket.recv(1024).decode('utf-8')
            
            if mensaje_escenario.startswith("ESCENARIO:"):
                self.escenario_seleccionado = int(mensaje_escenario.split(":")[1]) - 1
                print(f"Usando escenario {self.escenario_seleccionado+1} seleccionado por el servidor")
                print(f"p = {self.p[self.escenario_seleccionado]}")
                print(f"q = {self.q[self.escenario_seleccionado]}")
                print(f"g = {self.g[self.escenario_seleccionado]}")
            else:
                print(f"Respuesta inesperada del servidor: {mensaje_escenario}")
                return False
            
            # 2. Recibir la clave pública V del servidor
            mensaje_v = self.socket.recv(1024).decode('utf-8')
            
            if mensaje_v.startswith("V:"):
                V = int(mensaje_v.split(":")[1].strip())
                print(f"Recibida clave pública V={V} del servidor")
            else:
                print(f"Respuesta inesperada del servidor: {mensaje_v}")
                return False
            
            # 3. Generar clave privada
            p = self.p[self.escenario_seleccionado]
            q = self.q[self.escenario_seleccionado]
            g = self.g[self.escenario_seleccionado]
            a = random.randint(2, q - 1)
            
            # 4. Calcular y enviar clave pública
            U = pow(g, a, p)
            self.socket.send(f"U:{U}".encode('utf-8'))
            print(f"Enviada clave pública U={U} al servidor")
            
            # 5. Calcular secreto compartido
            secreto = pow(V, a, p)
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


# Bloque principal
if __name__ == "__main__": 
    cliente = ChatClient()
    try:
        cliente.iniciar()
    except KeyboardInterrupt:
        print("\nCliente detenido por el usuario")
    finally:
        cliente.desconectar()
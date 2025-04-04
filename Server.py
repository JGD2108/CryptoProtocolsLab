# servidor_oop.py
import socket
import threading
import random
import json

class ChatServer:
    def __init__(self, host='localhost', port=8888):
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
        self.escenario_seleccionado = 0  # Parámetros DH
        self.modo_comunicacion = 1  # 1: Diffie-Hellman, 2 y 3: otros modos
        self.secreto_compartido = None
    
    def inicializar_socket(self):
        """Configura el socket del servidor."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Servidor iniciado en {self.host}:{self.port}")
    
    def recibir_mensajes(self, cliente_socket, direccion):
        """Maneja la recepción de mensajes de un cliente específico."""
        while self.activo:
            try:
                # Recibir mensaje del cliente
                mensaje = cliente_socket.recv(1024).decode('utf-8')
                if not mensaje:
                    break
                    
                print(f"Mensaje recibido de {direccion}: {mensaje}")
                # No respondemos automáticamente, el hilo de envío se encargará de eso
                
            except Exception as e:
                print(f"Error con cliente {direccion}: {e}")
                break
        
        # Cerrar conexión cuando hay error o el cliente se desconecta
        self.desconectar_cliente(cliente_socket)
        print(f"Cliente {direccion} desconectado")
    
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
        # Usamos una copia de la lista para evitar problemas si se modifica durante el bucle
        for cliente in self.clientes[:]:  
            try:
                cliente.send(mensaje.encode('utf-8'))
            except:
                # Si hay error al enviar, el cliente probablemente se desconectó
                self.desconectar_cliente(cliente)
    
    def desconectar_cliente(self, cliente_socket):
        """Desconecta un cliente y limpia sus recursos."""
        if cliente_socket in self.clientes:
            self.clientes.remove(cliente_socket)
        try:
            cliente_socket.close()
        except:
            pass  # Ignorar errores al cerrar el socket
    
    def aceptar_conexiones(self):
        """Acepta nuevas conexiones de clientes."""
        try:
            while self.activo:
                try:
                    # Configurar timeout para poder verificar la bandera activo
                    self.socket.settimeout(1.0)  # 1 segundo de timeout
                    cliente_socket, direccion = self.socket.accept()
                    print(f"Nueva conexión de {direccion}")
                    
                    # Enviar el modo de comunicación seleccionado al cliente
                    cliente_socket.send(f"MODO:{self.modo_comunicacion}".encode('utf-8'))
                    print(f"Enviado modo de comunicación {self.modo_comunicacion} al cliente")
                    
                    # Manejar según el modo de comunicación seleccionado
                    if self.modo_comunicacion == 1:
                        # Modo 1: Diffie-Hellman
                        secreto = self.realizar_intercambio_diffie_hellman(cliente_socket, direccion)
                        if secreto:
                            print(f"Intercambio Diffie-Hellman completado con {direccion}. Secreto: {secreto}")
                            self.clientes.append(cliente_socket)
                            
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
                            
                    elif self.modo_comunicacion == 2:
                        # Modo 2: Placeholder para otro protocolo
                        print("Usando modo de comunicación 2")
                        self.manejar_modo_comunicacion_2(cliente_socket, direccion)
                        
                    elif self.modo_comunicacion == 3:
                        # Modo 3: Placeholder para otro protocolo
                        print("Usando modo de comunicación 3")
                        self.manejar_modo_comunicacion_3(cliente_socket, direccion)
                        
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
    
    def manejar_modo_comunicacion_2(self, cliente_socket, direccion):
        """Maneja el segundo modo de comunicación (placeholder)."""
        pass  # Implementar el segundo modo de comunicación aquí
    
    def manejar_modo_comunicacion_3(self, cliente_socket, direccion):
        """Maneja el tercer modo de comunicación (placeholder)."""
        pass  # Implementar el tercer modo de comunicación aquí
    
    def iniciar(self):
        """Inicia el servidor y todos sus hilos."""
        try:
            # Primero cargar parámetros
            self.cargar_parametros_diffie_hellman()
            
            # Seleccionar modo de comunicación
            try:
                modo = int(input("Ingrese el modo de comunicación (1: Diffie-Hellman, 2: Modo 2, 3: Modo 3): "))
                if 1 <= modo <= 3:
                    self.modo_comunicacion = modo
                    print(f"Usando modo de comunicación {modo}")
                    
                    # Si es Diffie-Hellman, también seleccionar escenario
                    if modo == 1:
                        self.seleccionar_escenario_diffie_hellman()
                else:
                    print("Número fuera de rango. Usando modo 1 (Diffie-Hellman) por defecto.")
                    self.modo_comunicacion = 1
                    self.seleccionar_escenario_diffie_hellman()
            except ValueError:
                print("Entrada inválida. Usando modo 1 (Diffie-Hellman) por defecto.")
                self.modo_comunicacion = 1
                self.seleccionar_escenario_diffie_hellman()
            
            # Inicializar socket y activar servidor
            self.inicializar_socket()
            self.activo = True
            
            # Crear e iniciar el hilo para enviar mensajes
            self.hilo_envio = threading.Thread(target=self.enviar_mensajes)
            self.hilo_envio.daemon = True
            self.hilo_envio.start()
            
            # Crear e iniciar el hilo para aceptar conexiones
            self.hilo_aceptacion = threading.Thread(target=self.aceptar_conexiones)
            self.hilo_aceptacion.daemon = True
            self.hilo_aceptacion.start()
            
            # Mantener el hilo principal vivo hasta que termine el hilo de envío
            self.hilo_envio.join()
            
        except KeyboardInterrupt:
            print("Servidor detenido")
            self.activo = False
        finally:
            self.detener()
    
    def seleccionar_escenario_diffie_hellman(self):
        """Selecciona el escenario para Diffie-Hellman."""
        try:
            num = int(input("Ingrese el número del escenario Diffie-Hellman (1 a 5): "))
            if 1 <= num <= 5:
                self.escenario_seleccionado = num - 1
                print(f"Usando escenario {num}:")
                print(f"p = {self.p[self.escenario_seleccionado]}")
                print(f"q = {self.q[self.escenario_seleccionado]}")
                print(f"g = {self.g[self.escenario_seleccionado]}")
            else:
                print("Número fuera de rango. Usando escenario 1 por defecto.")
                self.escenario_seleccionado = 0
        except ValueError:
            print("Entrada inválida. Usando escenario 1 por defecto.")
            self.escenario_seleccionado = 0
    
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
    
    def realizar_intercambio_diffie_hellman(self, cliente_socket, direccion):
        """Realiza el intercambio de claves Diffie-Hellman con un cliente, por turnos."""
        try:
            # Usar los parámetros del escenario seleccionado
            p = self.p[self.escenario_seleccionado]
            q = self.q[self.escenario_seleccionado]
            g = self.g[self.escenario_seleccionado]
            
            # 1. Enviar al cliente el escenario seleccionado
            cliente_socket.send(f"ESCENARIO:{self.escenario_seleccionado+1}".encode('utf-8'))
            print(f"Enviado escenario {self.escenario_seleccionado+1} al cliente")
            
            # 2. Generar clave privada del servidor
            a = random.randint(2, q - 1)
            
            # 3. Calcular y enviar clave pública del servidor
            V = pow(g, a, p)
            cliente_socket.send(f"V:{V}".encode('utf-8'))
            print(f"Enviada clave pública V={V} al cliente")
            
            # 4. Recibir clave pública del cliente
            mensaje_cliente = cliente_socket.recv(1024).decode('utf-8')
            
            # 5. Procesar respuesta del cliente
            if mensaje_cliente.startswith("U:"):
                U = int(mensaje_cliente.split(":")[1].strip())
                print(f"Recibida clave pública U={U} del cliente")
                
                # 6. Calcular el secreto compartido
                secreto = pow(U, a, p)
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
            return None
    
    def detener(self):
        """Detiene el servidor y limpia todos los recursos."""
        self.activo = False
        
        # Cerrar todas las conexiones
        for cliente in self.clientes[:]:
            self.desconectar_cliente(cliente)
            
        if self.socket:
            self.socket.close()
            
        print("Servidor cerrado")


# Bloque principal
if __name__ == "__main__":
    servidor = ChatServer()
    try:
        servidor.iniciar()
    except KeyboardInterrupt:
        print("\nServidor detenido por el usuario")
    finally:
        servidor.detener()
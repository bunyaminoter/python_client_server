"""
Server implementation for encrypted client-server communication
"""

import socket
import threading
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from encryption.ciphers import EncryptionManager


class Server:
    def __init__(self, host='127.0.0.1', port=8001):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = []
        self.encryption_manager = EncryptionManager()
        
    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            print(f"Sunucu başlatıldı: {self.host}:{self.port}")
            print("Bağlantı bekleniyor...")
            
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Yeni istemci bağlandı: {client_address}")
                
                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            print(f"Sunucu hatası: {e}")
        finally:
            self.stop()
    
    def handle_client(self, client_socket, client_address):
        """Handle individual client connection"""
        try:
            while True:
                # Receive message from client
                data = client_socket.recv(1024)
                if not data:
                    break
                
                try:
                    # Try to parse as JSON (encrypted message)
                    message_data = json.loads(data.decode('utf-8'))
                    encrypted_message = message_data.get('message', '')
                    encryption_method = message_data.get('method', 'none')
                    encryption_params = message_data.get('params', {})
                    
                    # Decrypt message
                    if encryption_method != 'none':
                        try:
                            decrypted_message = self.encryption_manager.decrypt(
                                encrypted_message, 
                                encryption_method, 
                                **encryption_params
                            )
                            print(f"Gelen mesaj (şifrelenmiş): {encrypted_message}")
                            print(f"Gelen mesaj (çözülmüş): {decrypted_message}")
                        except Exception as e:
                            print(f"Şifre çözme hatası: {e}")
                            decrypted_message = encrypted_message
                    else:
                        decrypted_message = encrypted_message
                        print(f"Gelen mesaj: {decrypted_message}")
                    
                    # Send response back to client
                    response = input(f"Sunucu yanıtı ({client_address}): ")
                    if response:
                        # Send response as JSON
                        response_data = {
                            'message': response,
                            'method': 'none',
                            'params': {}
                        }
                        response_json = json.dumps(response_data)
                        client_socket.send(response_json.encode('utf-8'))
                        print(f"Yanıt gönderildi: {response}")
                
                except json.JSONDecodeError:
                    # Handle plain text message
                    message = data.decode('utf-8')
                    print(f"Gelen mesaj (düz metin): {message}")
                    
                    response = input(f"Sunucu yanıtı ({client_address}): ")
                    if response:
                        client_socket.send(response.encode('utf-8'))
                        print(f"Yanıt gönderildi: {response}")
                
        except Exception as e:
            print(f"İstemci işleme hatası ({client_address}): {e}")
        finally:
            client_socket.close()
            print(f"İstemci bağlantısı kapatıldı: {client_address}")
    
    def stop(self):
        """Stop the server"""
        if self.server_socket:
            self.server_socket.close()
        print("Sunucu durduruldu.")


def main():
    print("=== Şifreli İstemci-Sunucu Uygulaması ===")
    print("Sunucu başlatılıyor...")
    
    server = Server()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nSunucu kapatılıyor...")
        server.stop()


if __name__ == "__main__":
    main()


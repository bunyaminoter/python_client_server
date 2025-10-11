"""
Client implementation with GUI for encrypted client-server communication
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from encryption.ciphers import EncryptionManager


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Şifreli İstemci-Sunucu Uygulaması")
        self.root.geometry("800x600")
        
        self.client_socket = None
        self.connected = False
        self.host = '127.0.0.1'
        self.port = 8001
        
        # Encryption manager
        self.encryption_manager = EncryptionManager()
        self.current_encryption = "none"
        self.encryption_params = {}
        
        self.setup_ui()
        self.connect_to_server()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Connection status
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(status_frame, text="Bağlantı Durumu:").grid(row=0, column=0, padx=(0, 5))
        self.status_label = ttk.Label(status_frame, text="Bağlanıyor...", foreground="orange")
        self.status_label.grid(row=0, column=1)
        
        
        # Encryption settings frame
        encryption_frame = ttk.LabelFrame(main_frame, text="Şifreleme Ayarları", padding="5")
        encryption_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Encryption method selection
        ttk.Label(encryption_frame, text="Şifreleme Yöntemi:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.encryption_var = tk.StringVar(value="none")
        encryption_combo = ttk.Combobox(
            encryption_frame, 
            textvariable=self.encryption_var,
            values=["none", "caesar", "vigenere", "substitution", "rail_fence", "affine"],
            state="readonly",
            width=15
        )
        encryption_combo.grid(row=0, column=1, padx=(0, 10))
        encryption_combo.bind('<<ComboboxSelected>>', self.on_encryption_changed)
        
        # Encryption parameters frame
        self.params_frame = ttk.Frame(encryption_frame)
        self.params_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Chat area
        chat_frame = ttk.LabelFrame(main_frame, text="Sohbet", padding="5")
        chat_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)
        
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, 
            height=15, 
            width=70, 
            state=tk.DISABLED,
            wrap=tk.WORD
        )
        self.chat_display.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Message input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))
        input_frame.columnconfigure(0, weight=1)
        
        self.message_entry = ttk.Entry(input_frame, font=("Arial", 10))
        self.message_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        self.message_entry.bind('<Return>', self.send_message)
        
        self.send_button = ttk.Button(input_frame, text="Gönder", command=self.send_message)
        self.send_button.grid(row=0, column=1)
        
        # Initialize encryption parameters
        self.setup_encryption_params()
    
    def setup_encryption_params(self):
        """Setup encryption parameter inputs"""
        # Clear existing widgets
        for widget in self.params_frame.winfo_children():
            widget.destroy()
        
        method = self.encryption_var.get()
        
        if method == "caesar":
            ttk.Label(self.params_frame, text="Kaydırma (Shift):").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.shift_var = tk.StringVar(value="3")
            ttk.Entry(self.params_frame, textvariable=self.shift_var, width=10).grid(row=0, column=1)
            
        elif method == "vigenere":
            ttk.Label(self.params_frame, text="Anahtar:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.key_var = tk.StringVar(value="KEY")
            ttk.Entry(self.params_frame, textvariable=self.key_var, width=15).grid(row=0, column=1)
            
        elif method == "substitution":
            ttk.Label(self.params_frame, text="Anahtar (26 harf):").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.substitution_key_var = tk.StringVar(value="QWERTYUIOPASDFGHJKLZXCVBNM")
            ttk.Entry(self.params_frame, textvariable=self.substitution_key_var, width=26).grid(row=0, column=1)
            ttk.Button(self.params_frame, text="Rastgele", command=self.generate_substitution_key).grid(row=0, column=2, padx=(5, 0))
            
        elif method == "rail_fence":
            ttk.Label(self.params_frame, text="Ray Sayısı:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.rails_var = tk.StringVar(value="3")
            ttk.Entry(self.params_frame, textvariable=self.rails_var, width=10).grid(row=0, column=1)
            
        elif method == "affine":
            ttk.Label(self.params_frame, text="A (1-25, 26 ile aralarında asal):").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.affine_a_var = tk.StringVar(value="5")
            ttk.Entry(self.params_frame, textvariable=self.affine_a_var, width=10).grid(row=0, column=1)
            ttk.Label(self.params_frame, text="B (0-25):").grid(row=1, column=0, sticky=tk.W, padx=(0, 5))
            self.affine_b_var = tk.StringVar(value="8")
            ttk.Entry(self.params_frame, textvariable=self.affine_b_var, width=10).grid(row=1, column=1)
    
    def generate_substitution_key(self):
        """Generate random substitution key"""
        import random
        chars = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        random.shuffle(chars)
        self.substitution_key_var.set(''.join(chars))
    
    def on_encryption_changed(self, event=None):
        """Handle encryption method change"""
        self.setup_encryption_params()
        self.update_encryption_settings()
    
    def update_encryption_settings(self):
        """Update encryption settings based on current parameters"""
        method = self.encryption_var.get()
        
        try:
            if method == "substitution":
                key = self.substitution_key_var.get()
                if len(key) == 26 and len(set(key.upper())) == 26:
                    self.encryption_manager.set_substitution_key(key)
                else:
                    messagebox.showerror("Hata", "Substitution anahtarı 26 farklı harf içermelidir!")
                    return
            elif method == "affine":
                a = int(self.affine_a_var.get())
                b = int(self.affine_b_var.get())
                self.encryption_manager.set_affine_keys(a, b)
            
            self.current_encryption = method
            self.encryption_params = self.get_encryption_params()
            
        except ValueError as e:
            messagebox.showerror("Hata", f"Geçersiz parametre: {e}")
    
    def get_encryption_params(self):
        """Get current encryption parameters"""
        method = self.encryption_var.get()
        params = {}
        
        if method == "caesar":
            params['shift'] = int(self.shift_var.get())
        elif method == "vigenere":
            params['key'] = self.key_var.get()
        elif method == "rail_fence":
            params['rails'] = int(self.rails_var.get())
        
        return params
    
    def connect_to_server(self):
        """Connect to server in separate thread"""
        def connect():
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((self.host, self.port))
                self.connected = True
                self.status_label.config(text="Bağlandı", foreground="green")
                self.display_message("Sunucuya bağlandı.")
                
                # Start listening for messages
                self.listen_for_messages()
                
            except Exception as e:
                self.status_label.config(text="Bağlantı Hatası", foreground="red")
                self.display_message(f"Bağlantı hatası: {e}")
        
        threading.Thread(target=connect, daemon=True).start()
    
    def listen_for_messages(self):
        """Listen for messages from server"""
        try:
            while self.connected:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                
                try:
                    # Try to parse as JSON
                    message_data = json.loads(data.decode('utf-8'))
                    message = message_data.get('message', '')
                    self.display_message(f"Sunucu: {message}")
                except json.JSONDecodeError:
                    # Handle plain text
                    message = data.decode('utf-8')
                    self.display_message(f"Sunucu: {message}")
                    
        except Exception as e:
            if self.connected:
                self.display_message(f"Bağlantı hatası: {e}")
                self.connected = False
                self.status_label.config(text="Bağlantı Kesildi", foreground="red")
    
    def send_message(self, event=None):
        """Send message to server"""
        if not self.connected:
            messagebox.showerror("Hata", "Sunucuya bağlı değil!")
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        try:
            # Update encryption settings
            self.update_encryption_settings()
            
            # Encrypt message if needed
            if self.current_encryption != "none":
                encrypted_message = self.encryption_manager.encrypt(
                    message, 
                    self.current_encryption, 
                    **self.encryption_params
                )
                self.display_message(f"Sen (şifrelenmiş): {encrypted_message}")
            else:
                encrypted_message = message
                self.display_message(f"Sen: {message}")
            
            # Prepare message data
            message_data = {
                'message': encrypted_message,
                'method': self.current_encryption,
                'params': self.encryption_params
            }
            
            # Send message
            self.client_socket.send(json.dumps(message_data).encode('utf-8'))
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Hata", f"Mesaj gönderme hatası: {e}")
    
    def display_message(self, message):
        """Display message in chat area"""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def on_closing(self):
        """Handle window closing"""
        self.connected = False
        if self.client_socket:
            self.client_socket.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = ClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()


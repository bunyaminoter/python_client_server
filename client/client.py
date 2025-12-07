"""
CLİENT (İstemci - Müşteri) arayüzü
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import json
import sys
import os
from encryption.rsa import RSACipher
import random
import string

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from encryption.ciphers import EncryptionManager


class ClientGUI:
    def __init__(self, root):
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

        # --- DÜZELTME BURADA: Bu fonksiyonu __init__'in dışına (sola) taşıdık ---
    def on_mode_changed(self):
            """Kütüphane modu değişince tetiklenir"""
            # Sadece AES ve DES için kütüphane modu aktiftir
            method = self.encryption_var.get()
            if method not in ["aes", "des"] and self.use_lib_var.get():
                messagebox.showinfo("Bilgi", "Kütüphane modu sadece AES ve DES için geçerlidir.")
                self.use_lib_var.set(False)
    
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
            values=["none", "caesar", "vigenere", "substitution", "rail_fence", "affine", 
                   "route", "columnar_transposition", "polybius", "pigpen", "hill", "aes", "des"],
            state="readonly",
            width=20
        )
        encryption_combo.grid(row=0, column=1, padx=(0, 10))
        encryption_combo.bind('<<ComboboxSelected>>', self.on_encryption_changed)
        # --- YENİ EKLENEN KISIM: Kütüphane Modu Checkbox ---
        self.use_lib_var = tk.BooleanVar(value=False)
        self.lib_check = ttk.Checkbutton(
            encryption_frame,
            text="Kütüphane Kullan (Mode 1)",
            variable=self.use_lib_var,
            command=self.on_mode_changed
        )
        self.lib_check.grid(row=0, column=2, padx=(5, 0))
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
            
        elif method == "route":
            ttk.Label(self.params_frame, text="Satır Sayısı:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.route_rows_var = tk.StringVar(value="3")
            ttk.Entry(self.params_frame, textvariable=self.route_rows_var, width=10).grid(row=0, column=1)
            ttk.Label(self.params_frame, text="Sütun Sayısı:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5))
            self.route_cols_var = tk.StringVar(value="3")
            ttk.Entry(self.params_frame, textvariable=self.route_cols_var, width=10).grid(row=1, column=1)
            ttk.Label(self.params_frame, text="Rota:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5))
            self.route_type_var = tk.StringVar(value="spiral")
            route_combo = ttk.Combobox(
                self.params_frame, 
                textvariable=self.route_type_var,
                values=["spiral", "row", "column", "diagonal"],
                state="readonly",
                width=10
            )
            route_combo.grid(row=2, column=1)
            
        elif method == "columnar_transposition":
            ttk.Label(self.params_frame, text="Anahtar:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.columnar_key_var = tk.StringVar(value="KEY")
            ttk.Entry(self.params_frame, textvariable=self.columnar_key_var, width=15).grid(row=0, column=1)
            
        elif method == "polybius":
            ttk.Label(self.params_frame, text="Alfabe (25 harf, I ve J aynı):").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.polybius_alphabet_var = tk.StringVar(value="ABCDEFGHIKLMNOPQRSTUVWXYZ")
            ttk.Entry(self.params_frame, textvariable=self.polybius_alphabet_var, width=25).grid(row=0, column=1)
            
        elif method == "pigpen":
            ttk.Label(self.params_frame, text="Pigpen şifreleme (otomatik başlatılır)").grid(row=0, column=0, sticky=tk.W)
            
        elif method == "hill":
            ttk.Label(self.params_frame, text="Anahtar Matris (2x2 veya 3x3):").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.hill_matrix_var = tk.StringVar(value="3,3,2,5")
            ttk.Entry(self.params_frame, textvariable=self.hill_matrix_var, width=20).grid(row=0, column=1)
            ttk.Label(self.params_frame, text="Örnek: 3,3,2,5 (2x2) veya 1,2,3,4,5,6,7,8,9 (3x3)").grid(row=1, column=0, columnspan=2, sticky=tk.W)
        
        elif method == "aes":
            ttk.Label(self.params_frame, text="AES Anahtarı:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.aes_key_var = tk.StringVar(value="varsayilan_aes_anahtari")
            ttk.Entry(self.params_frame, textvariable=self.aes_key_var, width=25).grid(row=0, column=1, sticky=tk.W)
            ttk.Label(self.params_frame, text="Opsiyonel IV:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5))
            self.aes_iv_var = tk.StringVar(value="")
            ttk.Entry(self.params_frame, textvariable=self.aes_iv_var, width=25).grid(row=1, column=1, sticky=tk.W)
            ttk.Label(self.params_frame, text="IV boş bırakılırsa otomatik üretilir (mesaja gömülür).").grid(row=2, column=0, columnspan=2, sticky=tk.W)

        elif method == "des":
            ttk.Label(self.params_frame, text="DES Anahtarı:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.des_key_var = tk.StringVar(value="varsayilan_des")
            ttk.Entry(self.params_frame, textvariable=self.des_key_var, width=25).grid(row=0, column=1, sticky=tk.W)
            ttk.Label(self.params_frame, text="Opsiyonel IV:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5))
            self.des_iv_var = tk.StringVar(value="")
            ttk.Entry(self.params_frame, textvariable=self.des_iv_var, width=25).grid(row=1, column=1, sticky=tk.W)
            ttk.Label(self.params_frame, text="Anahtar minimum 8 karakterdir, IV boşsa otomatik üretilir.").grid(row=2, column=0, columnspan=2, sticky=tk.W)
    
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
            elif method == "polybius":
                alphabet = self.polybius_alphabet_var.get()
                if len(alphabet) == 25 and len(set(alphabet.upper())) == 25:
                    self.encryption_manager.set_polybius_alphabet(alphabet)
                else:
                    messagebox.showerror("Hata", "Polybius alfabesi 25 farklı harf içermelidir!")
                    return
            elif method == "pigpen":
                self.encryption_manager.set_pigpen_cipher()
            elif method == "hill":
                matrix_str = self.hill_matrix_var.get()
                try:
                    matrix_values = [int(x.strip()) for x in matrix_str.split(',')]
                    if len(matrix_values) == 4:  # 2x2 matrix
                        key_matrix = [[matrix_values[0], matrix_values[1]], 
                                    [matrix_values[2], matrix_values[3]]]
                    elif len(matrix_values) == 9:  # 3x3 matrix
                        key_matrix = [[matrix_values[0], matrix_values[1], matrix_values[2]],
                                    [matrix_values[3], matrix_values[4], matrix_values[5]],
                                    [matrix_values[6], matrix_values[7], matrix_values[8]]]
                    else:
                        raise ValueError("Matris 4 (2x2) veya 9 (3x3) eleman içermelidir")
                    self.encryption_manager.set_hill_matrix(key_matrix)
                except ValueError as e:
                    messagebox.showerror("Hata", f"Geçersiz matris formatı: {e}")
                    return
            elif method in ("aes", "des"):
                key_value = self.aes_key_var.get() if method == "aes" else self.des_key_var.get()
                if not key_value:
                    messagebox.showerror("Hata", "Anahtar alanı boş bırakılamaz!")
                    return
            
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
        elif method == "route":
            params['rows'] = int(self.route_rows_var.get())
            params['cols'] = int(self.route_cols_var.get())
            params['route'] = self.route_type_var.get()
        elif method == "columnar_transposition":
            params['key'] = self.columnar_key_var.get()
        elif method == "aes":
            params['key'] = self.aes_key_var.get()
            if self.aes_iv_var.get():
                params['iv'] = self.aes_iv_var.get()
        elif method == "des":
            params['key'] = self.des_key_var.get()
            if self.des_iv_var.get():
                params['iv'] = self.des_iv_var.get()
        
        return params
    
    def connect_to_server(self):
        """Connect to server in separate thread"""
        def connect():
            try:
                self.client_socket.connect((self.host, self.port))

                self.client_socket.send("PUB_KEY_REQ".encode('utf-8'))
                resp = self.client_socket.recv(4096)
                resp_data = json.loads(resp.decode('utf-8'))

                if resp_data.get("type") == "PUB_KEY_RES":
                    self.server_public_key = tuple(resp_data["key"])
                    self.display_message("Sunucu RSA Public Key alındı.")
                # ---------------------------

                self.connected = True
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
                    encrypted_message = message_data.get('message', '')
                    method = message_data.get('method', 'none')
                    params = message_data.get('params', {})

                    if method != 'none':
                        # İlk önce gelen şifreli mesajı göster
                        self.display_message(f"Sunucu (şifreli): {encrypted_message}")
                        try:
                            decrypted = self.encryption_manager.decrypt(
                                encrypted_message,
                                method,
                                **params
                            )
                            # Ardından çözülmüş halini göster
                            self.display_message(f"Sunucu (çözüldü): {decrypted}")
                        except Exception as e:
                            self.display_message(f"Sunucu (şifre çözme hatası): {e}")
                    else:
                        # Şifreleme yoksa doğrudan mesajı göster
                        self.display_message(f"Sunucu: {encrypted_message}")
                except json.JSONDecodeError:
                    # Handle plain text
                    message = data.decode('utf-8')
                    self.display_message(f"Sunucu (düz): {message}")
                    
        except Exception as e:
            if self.connected:
                self.display_message(f"Bağlantı hatası: {e}")
                self.connected = False
                self.status_label.config(text="Bağlantı Kesildi", foreground="red")

    def send_message(self, event=None):
        """Send message to server"""
        # 1. Bağlantı Kontrolü
        if not self.connected:
            messagebox.showerror("Hata", "Sunucuya bağlı değil!")
            return

        # 2. Mesajı Al
        message = self.message_entry.get().strip()
        if not message:
            return

        try:
            # 3. Ayarları Güncelle
            self.update_encryption_settings()

            # 4. Gönderilen (düz) mesajı ekrana bas
            self.display_message(f"Sen (gönderilen): {message}")

            # 5. Mod Seçimi (Kütüphane vs Manuel)
            use_lib = self.use_lib_var.get()
            mode_str = "library" if use_lib else "manual"

            # --- HİBRİT + MOD SEÇİMLİ ŞİFRELEME (AES/DES ve RSA varsa) ---
            if self.current_encryption in ["aes", "des"] and hasattr(self, 'server_public_key'):
                # Rastgele oturum anahtarı oluştur (AES için 16, DES için 8 byte)
                key_len = 16 if self.current_encryption == "aes" else 8
                session_key = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))

                # Parametrelere bu yeni anahtarı ekle (Şifreleme fonksiyonu bu anahtarı kullanacak)
                self.encryption_params["key"] = session_key

                # Mesajı şifrele (Kütüphane veya Manuel mod tercihi 'use_lib' ile iletiliyor)
                encrypted_message = self.encryption_manager.encrypt(
                    message,
                    self.current_encryption,
                    use_lib=use_lib,
                    **self.encryption_params
                )

                # Oturum anahtarını Sunucunun RSA Public Key'i ile şifrele (Anahtar Dağıtımı)
                encrypted_session_key = RSACipher.encrypt(session_key, self.server_public_key)

                # Paketi hazırla
                message_data = {
                    'message': encrypted_message,
                    'method': self.current_encryption,
                    'encrypted_aes_key': encrypted_session_key,  # RSA ile şifrelenmiş anahtar
                    'params': self.encryption_params,  # IV vb. parametreler
                    'impl_mode': mode_str  # Sunucuya hangi modda çözmesi gerektiğini bildir
                }

                # Kullanıcıya Bilgi Ver (Raporlama ve Debug için)
                self.display_message(f"Mod: {mode_str.upper()}")
                self.display_message(f"Oturum Anahtarı (Random): {session_key}")
                self.display_message(f"Şifreli Mesaj: {encrypted_message}")

            else:
                # --- STANDART / DİĞER ŞİFRELEMELER (RSA yoksa veya Klasik yöntemlerse) ---
                if self.current_encryption != "none":
                    encrypted_message = self.encryption_manager.encrypt(
                        message,
                        self.current_encryption,
                        use_lib=use_lib,
                        **self.encryption_params
                    )
                    self.display_message(f"Sen ({mode_str}): {encrypted_message}")
                else:
                    encrypted_message = message

                message_data = {
                    'message': encrypted_message,
                    'method': self.current_encryption,
                    'params': self.encryption_params,
                    'impl_mode': mode_str
                }

            # 6. Veriyi Sunucuya Gönder
            self.client_socket.send(json.dumps(message_data).encode('utf-8'))

            # 7. Giriş kutusunu temizle
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


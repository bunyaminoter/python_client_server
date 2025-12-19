import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import json
import sys
import os
import random
import string

# Üst dizini path'e ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryption.ciphers import EncryptionManager
from encryption.rsa import RSACipher
from encryption.ecc import ECCCipher


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Şifreli İstemci (AES-DES-RSA-ECC)")
        self.root.geometry("900x750")

        self.client_socket = None
        self.connected = False
        self.host = '127.0.0.1'
        self.port = 8001

        # Sunucu Anahtarları
        self.server_rsa_pub = None
        self.server_ecc_pub = None

        self.encryption_manager = EncryptionManager()

        # GÜVENLİK GÜNCELLEMESİ: Son kullanılan oturum anahtarını hafızada tut
        self.current_session_key = None

        # UI Değişkenleri
        self.enc_method_var = tk.StringVar(value="none")
        self.key_dist_var = tk.StringVar(value="RSA")

        self.setup_ui()
        self.connect_to_server()

    def setup_ui(self):
        """Arayüzü oluşturur"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Bağlantı Durumu
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(status_frame, text="Durum:").pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_frame, text="Bağlanıyor...", foreground="orange")
        self.status_label.pack(side=tk.LEFT, padx=5)

        # 2. Ayarlar Çerçevesi
        settings_frame = ttk.LabelFrame(main_frame, text="Konfigürasyon", padding="5")
        settings_frame.pack(fill=tk.X, pady=5)

        # Üst Satır: Yöntem ve Dağıtım Seçimi
        top_settings = ttk.Frame(settings_frame)
        top_settings.pack(fill=tk.X, pady=5)

        ttk.Label(top_settings, text="Şifreleme:").pack(side=tk.LEFT)

        # Tüm seçenekleri içeren liste
        opts = [
            "none", "caesar", "vigenere", "substitution", "rail_fence", "affine",
            "route", "columnar_transposition", "polybius", "pigpen", "hill",
            "AES (Manuel)", "AES (Kütüphane)",
            "DES (Manuel)", "DES (Kütüphane)",
            "RSA (Direkt)"
        ]
        self.combo_enc = ttk.Combobox(top_settings, textvariable=self.enc_method_var, values=opts, state="readonly",
                                      width=20)
        self.combo_enc.pack(side=tk.LEFT, padx=5)
        self.combo_enc.bind("<<ComboboxSelected>>", self.on_method_change)

        ttk.Label(top_settings, text="Anahtar Dağıtımı:").pack(side=tk.LEFT, padx=(15, 0))
        ttk.Radiobutton(top_settings, text="RSA", variable=self.key_dist_var, value="RSA").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(top_settings, text="ECC (Diffie-Hellman)", variable=self.key_dist_var, value="ECC").pack(
            side=tk.LEFT, padx=2)

        # Alt Satır: Dinamik Parametreler
        self.params_frame = ttk.Frame(settings_frame)
        self.params_frame.pack(fill=tk.X, pady=5)

        # 3. Sohbet Ekranı
        chat_frame = ttk.LabelFrame(main_frame, text="İletişim Logu", padding="5")
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.chat_display = scrolledtext.ScrolledText(chat_frame, height=20, state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        # 4. Giriş Alanı
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X)

        self.msg_entry = ttk.Entry(input_frame, font=("Arial", 10))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.msg_entry.bind('<Return>', self.send_message)
        ttk.Button(input_frame, text="Gönder", command=self.send_message).pack(side=tk.RIGHT)

        # Varsayılan parametre ekranını yükle
        self.setup_params_ui()

    def parse_selection(self):
        """Seçilen yöntemi ve kütüphane modunu ayrıştırır"""
        sel = self.enc_method_var.get()
        method = sel.split(" ")[0].lower()
        use_lib = "(Kütüphane)" in sel
        return method, use_lib

    def setup_params_ui(self):
        """Seçilen şifreleme yöntemine göre giriş kutularını oluşturur"""
        for w in self.params_frame.winfo_children(): w.destroy()
        method, _ = self.parse_selection()

        if method in ["aes", "des"]:
            lbl = f"{method.upper()} Anahtarı:"
            ttk.Label(self.params_frame, text=lbl).pack(side=tk.LEFT)
            self.key_entry_var = tk.StringVar(value="(Otomatik Üretilecek)")
            ttk.Entry(self.params_frame, textvariable=self.key_entry_var, state="readonly", width=25).pack(side=tk.LEFT,
                                                                                                           padx=5)

        elif method == "caesar":
            ttk.Label(self.params_frame, text="Shift (Kaydırma):").pack(side=tk.LEFT)
            self.shift_var = tk.StringVar(value="3")
            ttk.Entry(self.params_frame, textvariable=self.shift_var, width=5).pack(side=tk.LEFT, padx=5)

        elif method == "vigenere":
            ttk.Label(self.params_frame, text="Anahtar Kelime:").pack(side=tk.LEFT)
            self.vigenere_key_var = tk.StringVar(value="KEY")
            ttk.Entry(self.params_frame, textvariable=self.vigenere_key_var, width=15).pack(side=tk.LEFT, padx=5)

        elif method == "affine":
            ttk.Label(self.params_frame, text="a:").pack(side=tk.LEFT)
            self.aff_a = tk.StringVar(value="5")
            ttk.Entry(self.params_frame, textvariable=self.aff_a, width=5).pack(side=tk.LEFT, padx=2)
            ttk.Label(self.params_frame, text="b:").pack(side=tk.LEFT)
            self.aff_b = tk.StringVar(value="8")
            ttk.Entry(self.params_frame, textvariable=self.aff_b, width=5).pack(side=tk.LEFT, padx=2)

        elif method == "rail_fence":
            ttk.Label(self.params_frame, text="Ray Sayısı:").pack(side=tk.LEFT)
            self.rails_var = tk.StringVar(value="3")
            ttk.Entry(self.params_frame, textvariable=self.rails_var, width=5).pack(side=tk.LEFT, padx=5)

        elif method == "columnar_transposition":
            ttk.Label(self.params_frame, text="Anahtar:").pack(side=tk.LEFT)
            self.col_key_var = tk.StringVar(value="KEY")
            ttk.Entry(self.params_frame, textvariable=self.col_key_var, width=15).pack(side=tk.LEFT, padx=5)

    def on_method_change(self, event):
        self.setup_params_ui()

    def get_ui_params(self):
        """Arayüzden girilen parametreleri toplar (Basit şifrelemeler için)"""
        method, _ = self.parse_selection()
        params = {}
        try:
            if method == "caesar":
                params["shift"] = int(self.shift_var.get())
            elif method == "vigenere":
                params["key"] = self.vigenere_key_var.get()
            elif method == "affine":
                params["a"] = int(self.aff_a.get())
                params["b"] = int(self.aff_b.get())
            elif method == "rail_fence":
                params["rails"] = int(self.rails_var.get())
            elif method == "columnar_transposition":
                params["key"] = self.col_key_var.get()
            # Diğer metodlar eklenebilir...
        except ValueError:
            pass  # Hatalı giriş varsa varsayılanlar veya boş gider
        return params

    def log_output(self, sender, method, key, raw_cipher, plain, is_self=False):
        """Formatlı Loglama"""
        self.chat_display.config(state=tk.NORMAL)

        cipher_show = str(raw_cipher)
        if len(cipher_show) > 50: cipher_show = cipher_show[:50] + "..."

        text_block = (
            f"\nYöntem: {method}\n"
            f"Oturum Anahtarı: {key}\n"
            f"{sender} ({method.split(' ')[0]}): {cipher_show}\n"
            f"{sender} (çözüldü): {plain}\n"
            f"{'-' * 40}"
        )

        self.chat_display.insert(tk.END, text_block + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def connect_to_server(self):
        def run():
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((self.host, self.port))

                # Handshake
                self.client_socket.send("PUB_KEY_REQ".encode('utf-8'))
                resp = self.client_socket.recv(8192)
                data = json.loads(resp.decode('utf-8'))

                self.server_rsa_pub = tuple(data["rsa_pub"])
                self.server_ecc_pub = tuple(data["ecc_pub"])

                self.connected = True
                self.root.after(0, lambda: self.status_label.config(text="Bağlandı", foreground="green"))
                self.listen()
            except Exception as e:
                self.root.after(0, lambda: self.status_label.config(text="Hata", foreground="red"))

        threading.Thread(target=run, daemon=True).start()

    def listen(self):
        while self.connected:
            try:
                data = self.client_socket.recv(8192)
                if not data: break

                msg_data = json.loads(data.decode('utf-8'))
                method = msg_data.get('method')
                impl_mode = msg_data.get('impl_mode')
                enc_msg = msg_data.get('message')
                params = msg_data.get('params', {})
                key_dist = msg_data.get('key_dist', 'RSA')

                session_key = "Bilinmiyor"
                decrypted_msg = ""

                # GÜVENLİK GÜNCELLEMESİ (Receiver Side)
                # 1. Eğer params içinde key varsa (eski usül/güvensiz) onu kullan
                if method in ["aes", "des"]:
                    if 'key' in params:
                        session_key = params['key']
                    # 2. Key yoksa hafızadaki son anahtarı kullan (GÜVENLİ)
                    elif self.current_session_key:
                        session_key = self.current_session_key
                        # Şifre çözücü fonksiyona göndermek için params içine ekle
                        params['key'] = session_key

                # 2. Mesajı Çöz
                use_lib = (impl_mode == 'library')

                if method == 'rsa':
                    # RSA Direkt Mesaj (Private Key yok, çözülemez simülasyonu)
                    decrypted_msg = "<RSA Şifreli Veri - Private Key Gerekli>"
                    session_key = "RSA-Public"
                elif method != 'none':
                    try:
                        decrypted_msg = self.encryption_manager.decrypt(enc_msg, method, use_lib=use_lib, **params)
                    except Exception as e:
                        decrypted_msg = f"Hata: {e}"
                else:
                    decrypted_msg = enc_msg

                # Ekrana Bas
                mode_txt = f"{method} ({impl_mode})" if method in ['aes', 'des'] else method
                self.root.after(0, lambda: self.log_output(
                    "Sunucu", mode_txt, session_key, enc_msg, decrypted_msg, is_self=False
                ))

            except Exception:
                self.connected = False
                break

    def send_message(self, event=None):
        if not self.connected: return
        msg = self.msg_entry.get().strip()
        if not msg: return

        method, use_lib = self.parse_selection()
        dist_method = self.key_dist_var.get()
        mode_str = "library" if use_lib else "manual"

        session_key = "-"
        final_payload = {}
        params = {}

        try:
            # --- SENARYO 1: RSA DIRECT (Mesaj Şifreleme) ---
            if method == "rsa":
                enc_int = RSACipher.encrypt(msg, self.server_rsa_pub)
                final_payload = {
                    'message': enc_int,
                    'method': 'rsa',
                    'impl_mode': 'manual',
                    'params': {}
                }
                session_key = "RSA-Public"
                enc_msg_display = str(enc_int)

            # --- SENARYO 2: HİBRİT (AES/DES + RSA/ECC) ---
            elif method in ["aes", "des"]:
                key_len = 16 if method == "aes" else 8

                # A) Anahtar Dağıtımı (Key Distribution)
                if dist_method == "RSA":
                    session_key = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
                    enc_session_key = RSACipher.encrypt(session_key, self.server_rsa_pub)
                    final_payload['encrypted_key'] = enc_session_key
                    final_payload['key_dist'] = 'RSA'

                elif dist_method == "ECC":
                    client_ecc = ECCCipher()
                    full_secret = client_ecc.generate_shared_secret(self.server_ecc_pub)
                    session_key = full_secret[:key_len]
                    final_payload['ecc_public_key'] = client_ecc.public_key
                    final_payload['key_dist'] = 'ECC'

                # B) Anahtarı Hafızaya Kaydet (Sunucudan geri dönmeyecek!)
                self.current_session_key = session_key

                # C) Mesaj Şifreleme
                params = {"key": session_key}
                enc_msg = self.encryption_manager.encrypt(msg, method, use_lib=use_lib, **params)
                enc_msg_display = enc_msg

                # D) GÜVENLİK DÜZELTMESİ:
                # Ağ paketine koyulacak parametrelerden 'key'i siliyoruz.
                payload_params = params.copy()
                if 'key' in payload_params:
                    del payload_params['key']

                final_payload.update({
                    'message': enc_msg,
                    'method': method,
                    'impl_mode': mode_str,
                    'params': payload_params  # Key içermeyen parametreler
                })

            # --- SENARYO 3: BASİT ŞİFRELEMELER (Caesar vb.) ---
            else:
                params = self.get_ui_params()  # Arayüzden parametreleri topla

                if method != "none":
                    enc_msg = self.encryption_manager.encrypt(msg, method, use_lib=use_lib, **params)
                else:
                    enc_msg = msg

                enc_msg_display = enc_msg
                final_payload = {
                    'message': enc_msg,
                    'method': method,
                    'impl_mode': mode_str,
                    'params': params
                }

            # GÖNDER VE LOGLA
            self.client_socket.send(json.dumps(final_payload).encode('utf-8'))

            disp_method = f"{method} ({mode_str})" if method in ['aes', 'des'] else method
            self.log_output("Sen", disp_method, session_key, enc_msg_display, msg, is_self=True)

            self.msg_entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("Hata", f"Gönderim Hatası: {e}")


def main():
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
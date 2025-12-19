import json
import os
import socket
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Üst dizini (encryption klasörünü bulabilmesi için) path'e ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryption.ciphers import EncryptionManager
from encryption.rsa import RSACipher
from encryption.ecc import ECCCipher


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Şifreli Sunucu (AES-DES-RSA-ECC)")
        self.root.geometry("900x750")

        self.host = '127.0.0.1'
        self.port = 8001
        self.server_socket = None
        self.client_socket = None
        self.connected = False
        self.running = True

        self.enc_manager = EncryptionManager()

        # UI Değişkenleri
        self.enc_method_var = tk.StringVar(value="none")
        self.status_var = tk.StringVar(value="Başlatılıyor...")

        # 1. ARAYÜZÜ OLUŞTUR
        self.setup_ui()

        # 2. LOGLAMA VE KRİPTOGRAFİK KURULUM
        self.log_gui("Sistem başlatılıyor...")

        self.rsa = RSACipher(key_size=1024)
        self.log_gui("RSA Anahtar Çifti (1024-bit) üretildi.")

        self.ecc = ECCCipher()
        self.log_gui("ECC (secp256k1) Anahtar Çifti üretildi.")

        # Sunucuyu Başlat
        threading.Thread(target=self.start_server, daemon=True).start()

    def setup_ui(self):
        """Arayüz Kurulumu"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Durum Paneli
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(status_frame, text="Durum:").pack(side=tk.LEFT)

        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, foreground="orange",
                                      font=("Arial", 10, "bold"))
        self.status_label.pack(side=tk.LEFT, padx=5)

        ttk.Label(status_frame, text=f"({self.host}:{self.port})").pack(side=tk.RIGHT)

        # 2. Şifreleme Ayarları
        settings_frame = ttk.LabelFrame(main_frame, text="Şifreleme Ayarları (Giden/Gelen)", padding="5")
        settings_frame.pack(fill=tk.X, pady=5)

        ttk.Label(settings_frame, text="Yöntem:").pack(side=tk.LEFT)

        options = [
            "none", "caesar", "vigenere", "substitution", "rail_fence", "affine",
            "route", "columnar_transposition", "polybius", "pigpen", "hill",
            "AES (Manuel)", "AES (Kütüphane)",
            "DES (Manuel)", "DES (Kütüphane)",
            "RSA (Direkt)"
        ]

        self.combo_enc = ttk.Combobox(settings_frame, textvariable=self.enc_method_var, values=options,
                                      state="readonly", width=25)
        self.combo_enc.pack(side=tk.LEFT, padx=5)
        self.combo_enc.bind("<<ComboboxSelected>>", self.on_method_change)

        # Parametre Alanı
        self.params_frame = ttk.Frame(settings_frame)
        self.params_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)

        # 3. Sohbet / Log Ekranı
        chat_frame = ttk.LabelFrame(main_frame, text="İletişim Logu", padding="5")
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.chat_display = scrolledtext.ScrolledText(chat_frame, height=20, state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        # 4. Mesaj Gönderme Alanı
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X)

        self.msg_entry = ttk.Entry(input_frame, font=("Arial", 10))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", self.send_message)
        ttk.Button(input_frame, text="Gönder", command=self.send_message).pack(side=tk.RIGHT)

        self.setup_params_ui()

    def update_status(self, text, color):
        """Durum çubuğunu güvenli şekilde günceller"""
        self.root.after(0, lambda: [
            self.status_var.set(text),
            self.status_label.config(foreground=color)
        ])

    def parse_selection(self):
        sel = self.enc_method_var.get()
        method = sel.split(" ")[0].lower()
        use_lib = "(Kütüphane)" in sel
        return method, use_lib

    def setup_params_ui(self):
        for w in self.params_frame.winfo_children(): w.destroy()
        method, _ = self.parse_selection()

        if method in ["aes", "des"]:
            ttk.Label(self.params_frame, text="Anahtar:").pack(side=tk.LEFT)
            self.key_var = tk.StringVar(value="")
            ttk.Entry(self.params_frame, textvariable=self.key_var, width=20).pack(side=tk.LEFT, padx=5)
            ttk.Label(self.params_frame, text="(Gelen mesajdan alınır)").pack(side=tk.LEFT)
        elif method == "caesar":
            ttk.Label(self.params_frame, text="Shift:").pack(side=tk.LEFT)
            self.shift_var = tk.StringVar(value="3")
            ttk.Entry(self.params_frame, textvariable=self.shift_var, width=5).pack(side=tk.LEFT)

    def on_method_change(self, event):
        self.setup_params_ui()

    def log_gui(self, text):
        self.root.after(0, lambda: self._append_text(f"[SİSTEM]: {text}\n"))

    def log_transaction(self, sender, method, key, cipher, plain):
        cipher_show = str(cipher)
        if len(cipher_show) > 50: cipher_show = cipher_show[:50] + "..."
        msg = (
            f"\nYöntem: {method}\n"
            f"Oturum Anahtarı: {key}\n"
            f"{sender} ({method.split(' ')[0]}): {cipher_show}\n"
            f"{sender} (çözüldü): {plain}\n"
            f"{'-' * 40}\n"
        )
        self.root.after(0, lambda: self._append_text(msg))

    def _append_text(self, text):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, text)
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))

            self.server_socket.listen(1)
            self.update_status("İstemci Bekleniyor... (Dinleniyor)", "blue")
            self.log_gui(f"Sunucu {self.port} portunda dinlemeye başladı.")

            client, addr = self.server_socket.accept()
            self.client_socket = client
            self.connected = True

            self.update_status(f"Bağlandı: {addr[0]}", "green")
            self.log_gui(f"İstemci bağlandı: {addr}")

            self.listen()
        except Exception as e:
            self.update_status("Hata Oluştu", "red")
            self.log_gui(f"Sunucu Başlatma Hatası: {e}")

    def listen(self):
        while self.connected:
            try:
                data = self.client_socket.recv(8192)
                if not data: break

                txt = data.decode('utf-8')

                if txt == "PUB_KEY_REQ":
                    resp = {"rsa_pub": self.rsa.public_key, "ecc_pub": self.ecc.public_key}
                    self.client_socket.send(json.dumps(resp).encode('utf-8'))
                    self.log_gui("Public Keyler (RSA + ECC) gönderildi.")
                    continue

                self.process_incoming_message(json.loads(txt))
            except Exception as e:
                self.log_gui(f"Bağlantı hatası: {e}")
                break

        self.connected = False
        self.update_status("Bağlantı Kesildi", "red")

    def process_incoming_message(self, data):
        method = data.get('method')
        impl_mode = data.get('impl_mode', 'manual')
        enc_msg = data.get('message')
        key_dist = data.get('key_dist', 'RSA')
        params = data.get('params', {})

        session_key = "Yok"
        decrypted_msg = ""

        # 1. Anahtarı Çöz / Türet
        if method in ["aes", "des"]:
            key_len = 16 if method == "aes" else 8

            if key_dist == "RSA" and 'encrypted_key' in data:
                session_key = self.rsa.decrypt(data['encrypted_key'], self.rsa.private_key)
            elif key_dist == "ECC" and 'ecc_public_key' in data:
                full_secret = self.ecc.generate_shared_secret(tuple(data['ecc_public_key']))
                session_key = full_secret[:key_len]
            elif 'key' in params: # Fallback
                session_key = params['key']

            # Decrypt işlemi için anahtarı params'a koyuyoruz (fakat sonraki yanıtta göndermeyeceğiz)
            params['key'] = session_key

            # 2. Arayüzü Güncelle (Otomatik Algılama)
            combo_val = method.upper()
            if impl_mode == "library":
                combo_val += " (Kütüphane)"
            else:
                combo_val += " (Manuel)"

            def update_ui_safe():
                self.enc_method_var.set(combo_val)
                self.setup_params_ui()
                if hasattr(self, 'key_var'): self.key_var.set(session_key)

            self.root.after(0, update_ui_safe)

        # 3. Mesajı Çöz
        try:
            use_lib = (impl_mode == 'library')
            if method == 'rsa':
                decrypted_msg = self.rsa.decrypt(enc_msg, self.rsa.private_key)
                session_key = "RSA-Private"
            elif method != 'none':
                decrypted_msg = self.enc_manager.decrypt(enc_msg, method, use_lib=use_lib, **params)
            else:
                decrypted_msg = enc_msg

            mode_display = f"{method} ({impl_mode})" if method in ['aes', 'des'] else method
            self.log_transaction("İstemci", mode_display, session_key, enc_msg, decrypted_msg)

        except Exception as e:
            self.log_gui(f"Şifre çözme hatası: {e}")

    def send_message(self, event=None):
        if not self.connected: return
        msg = self.msg_entry.get().strip()
        if not msg: return

        method, use_lib = self.parse_selection()
        mode_str = "library" if use_lib else "manual"
        params = {}

        try:
            # Parametreleri topla
            if method in ["aes", "des"]:
                key = self.key_var.get()
                if not key:
                    messagebox.showerror("Hata", "AES/DES için bir anahtar girin veya bekleyin.")
                    return
                params["key"] = key
            elif method == "caesar":
                params["shift"] = int(self.shift_var.get())

            # Şifrele
            if method != "none" and method != "rsa":
                enc_msg = self.enc_manager.encrypt(msg, method, use_lib=use_lib, **params)
            else:
                enc_msg = msg

            # GÜVENLİK DÜZELTMESİ (Server Side):
            # Cevap verirken anahtarı pakete koyma! İstemci zaten biliyor.
            payload_params = params.copy()
            if 'key' in payload_params:
                del payload_params['key']

            # Gönder
            payload = {
                'message': enc_msg,
                'method': method if method != 'rsa' else 'none',
                'params': payload_params,
                'impl_mode': mode_str
            }

            self.client_socket.send(json.dumps(payload).encode('utf-8'))

            # Logla
            disp_method = f"{method} ({mode_str})" if method in ['aes', 'des'] else method
            self.log_transaction("Sunucu", disp_method, params.get("key", "-"), enc_msg, msg)
            self.msg_entry.delete(0, tk.END)

        except Exception as e:
            self.log_gui(f"Gönderme hatası: {e}")

    def on_closing(self):
        self.connected = False
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = ServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
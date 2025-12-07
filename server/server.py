"""
GUI tabanlı sunucu uygulaması (şifreli istemci-sunucu iletişimi).
Sunucu penceresi, istemciden gelen şifreli mesajı ve çözülmüş halini
sırayla gösterir; sunucudan gönderilen mesajlarda da önce düz metin,
ardından şifrelenmiş metin görüntülenir.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from typing import List
from encryption.rsa import RSACipher

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from encryption.ciphers import EncryptionManager


class ServerGUI:
    def __init__(self, root: tk.Tk, host: str = "127.0.0.1", port: int = 8001):
        self.root = root
        self.root.title("Şifreli Sunucu")
        self.root.geometry("800x600")

        self.host = host
        self.port = port
        self.server_socket: socket.socket | None = None
        self.client_socket: socket.socket | None = None
        self.client_address: tuple | None = None
        self.running = False
        self.client_connected = False

        self.encryption_manager = EncryptionManager()

        from encryption.rsa import RSACipher  # (Eğer dosyanın başında import etmediyseniz)

        self._safe_status("RSA Anahtarları üretiliyor...", "orange")
        self.rsa_cipher = RSACipher(key_size=1024)  # RSA nesnesini başlat
        self.server_public_key = self.rsa_cipher.public_key  # İstemcilere dağıtılacak anahtar
        print("RSA Anahtarları oluşturuldu.")

        self.current_encryption = "none"
        self.encryption_params: dict = {}

        self._build_ui()
        self._start_server_thread()

    # ----------------- UI -----------------
    def _build_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)

        # Durum satırı
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(status_frame, text="Sunucu Durumu:").grid(row=0, column=0, padx=(0, 5))
        self.status_label = ttk.Label(status_frame, text="Başlatılıyor...", foreground="orange")
        self.status_label.grid(row=0, column=1)

        ttk.Label(status_frame, text=f"Adres: {self.host}:{self.port}").grid(row=0, column=2, padx=(15, 0))

        # Şifreleme ayarları
        encryption_frame = ttk.LabelFrame(main_frame, text="Şifreleme Ayarları", padding="5")
        encryption_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(encryption_frame, text="Şifreleme Yöntemi:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.encryption_var = tk.StringVar(value="none")
        encryption_combo = ttk.Combobox(
            encryption_frame,
            textvariable=self.encryption_var,
            values=[
                "none",
                "caesar",
                "vigenere",
                "substitution",
                "rail_fence",
                "affine",
                "route",
                "columnar_transposition",
                "polybius",
                "pigpen",
                "hill",
                "aes",
                "des",
            ],
            state="readonly",
            width=20,
        )
        encryption_combo.grid(row=0, column=1, padx=(0, 10))
        encryption_combo.bind("<<ComboboxSelected>>", self.on_encryption_changed)

        self.use_lib_var = tk.BooleanVar(value=False)
        self.lib_check = ttk.Checkbutton(
            encryption_frame,
            text="Kütüphane Kullan",
            variable=self.use_lib_var
        )
        self.lib_check.grid(row=0, column=2, padx=(5, 0))

        self.params_frame = ttk.Frame(encryption_frame)
        self.params_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))

        # Sohbet alanı
        chat_frame = ttk.LabelFrame(main_frame, text="Sunucu Sohbet Penceresi", padding="5")
        chat_frame.grid(row=3, column=0, sticky=(tk.N, tk.S, tk.E, tk.W), pady=(0, 10))
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            height=18,
            width=70,
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self.chat_display.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

        # Mesaj giriş alanı
        input_frame = ttk.Frame(main_frame)
        input_frame.grid(row=4, column=0, sticky=(tk.W, tk.E))
        input_frame.columnconfigure(0, weight=1)

        self.message_entry = ttk.Entry(input_frame, font=("Arial", 10))
        self.message_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = ttk.Button(input_frame, text="Gönder", command=self.send_message)
        self.send_button.grid(row=0, column=1)

        self._setup_encryption_params()

    # ------------- Encryption settings (benzer client ile) -------------
    def _setup_encryption_params(self):
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

        elif method == "rail_fence":
            ttk.Label(self.params_frame, text="Ray Sayısı:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.rails_var = tk.StringVar(value="3")
            ttk.Entry(self.params_frame, textvariable=self.rails_var, width=10).grid(row=0, column=1)

        elif method == "affine":
            ttk.Label(self.params_frame, text="A (1-25, 26 ile aralarında asal):").grid(
                row=0, column=0, sticky=tk.W, padx=(0, 5)
            )
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
                width=10,
            )
            route_combo.grid(row=2, column=1)

        elif method == "columnar_transposition":
            ttk.Label(self.params_frame, text="Anahtar:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.columnar_key_var = tk.StringVar(value="KEY")
            ttk.Entry(self.params_frame, textvariable=self.columnar_key_var, width=15).grid(row=0, column=1)

        elif method == "polybius":
            ttk.Label(self.params_frame, text="Alfabe (25 harf, I ve J aynı):").grid(
                row=0, column=0, sticky=tk.W, padx=(0, 5)
            )
            self.polybius_alphabet_var = tk.StringVar(value="ABCDEFGHIKLMNOPQRSTUVWXYZ")
            ttk.Entry(self.params_frame, textvariable=self.polybius_alphabet_var, width=25).grid(row=0, column=1)

        elif method == "pigpen":
            ttk.Label(self.params_frame, text="Pigpen şifreleme (otomatik başlatılır)").grid(
                row=0, column=0, sticky=tk.W
            )

        elif method == "hill":
            ttk.Label(self.params_frame, text="Anahtar Matris (2x2 veya 3x3):").grid(
                row=0, column=0, sticky=tk.W, padx=(0, 5)
            )
            self.hill_matrix_var = tk.StringVar(value="3,3,2,5")
            ttk.Entry(self.params_frame, textvariable=self.hill_matrix_var, width=20).grid(row=0, column=1)
            ttk.Label(
                self.params_frame,
                text="Örnek: 3,3,2,5 (2x2) veya 1,2,3,4,5,6,7,8,9 (3x3)",
            ).grid(row=1, column=0, columnspan=2, sticky=tk.W)

        elif method == "aes":
            ttk.Label(self.params_frame, text="AES Anahtarı:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.aes_key_var = tk.StringVar(value="varsayilan_aes_anahtari")
            ttk.Entry(self.params_frame, textvariable=self.aes_key_var, width=25).grid(
                row=0, column=1, sticky=tk.W
            )
            ttk.Label(self.params_frame, text="Opsiyonel IV:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5))
            self.aes_iv_var = tk.StringVar(value="")
            ttk.Entry(self.params_frame, textvariable=self.aes_iv_var, width=25).grid(
                row=1, column=1, sticky=tk.W
            )

        elif method == "des":
            ttk.Label(self.params_frame, text="DES Anahtarı:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
            self.des_key_var = tk.StringVar(value="varsayilan_des")
            ttk.Entry(self.params_frame, textvariable=self.des_key_var, width=25).grid(
                row=0, column=1, sticky=tk.W
            )
            ttk.Label(self.params_frame, text="Opsiyonel IV:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5))
            self.des_iv_var = tk.StringVar(value="")
            ttk.Entry(self.params_frame, textvariable=self.des_iv_var, width=25).grid(
                row=1, column=1, sticky=tk.W
            )

    def on_encryption_changed(self, event=None):
        self._setup_encryption_params()
        self._update_encryption_settings()

    def _update_encryption_settings(self):
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
                values = [int(x.strip()) for x in matrix_str.split(",")]
                if len(values) == 4:
                    key_matrix: List[List[int]] = [[values[0], values[1]], [values[2], values[3]]]
                elif len(values) == 9:
                    key_matrix = [
                        [values[0], values[1], values[2]],
                        [values[3], values[4], values[5]],
                        [values[6], values[7], values[8]],
                    ]
                else:
                    raise ValueError("Matris 4 (2x2) veya 9 (3x3) eleman içermelidir")
                self.encryption_manager.set_hill_matrix(key_matrix)
            elif method in ("aes", "des"):
                key_value = self.aes_key_var.get() if method == "aes" else self.des_key_var.get()
                if not key_value:
                    messagebox.showerror("Hata", "Anahtar alanı boş bırakılamaz!")
                    return

            self.current_encryption = method
            self.encryption_params = self._get_encryption_params()
        except ValueError as e:
            messagebox.showerror("Hata", f"Geçersiz parametre: {e}")

    def _get_encryption_params(self) -> dict:
        method = self.encryption_var.get()
        params: dict = {}

        if method == "caesar":
            params["shift"] = int(self.shift_var.get())
        elif method == "vigenere":
            params["key"] = self.key_var.get()
        elif method == "rail_fence":
            params["rails"] = int(self.rails_var.get())
        elif method == "route":
            params["rows"] = int(self.route_rows_var.get())
            params["cols"] = int(self.route_cols_var.get())
            params["route"] = self.route_type_var.get()
        elif method == "columnar_transposition":
            params["key"] = self.columnar_key_var.get()
        elif method == "aes":
            params["key"] = self.aes_key_var.get()
            if self.aes_iv_var.get():
                params["iv"] = self.aes_iv_var.get()
        elif method == "des":
            params["key"] = self.des_key_var.get()
            if self.des_iv_var.get():
                params["iv"] = self.des_iv_var.get()

        return params

    # ------------- Networking -------------
    def _start_server_thread(self):
        def run_server():
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind((self.host, self.port))
                self.server_socket.listen(1)

                self.running = True
                self._safe_status("İstemci bekleniyor...", "orange")

                client_socket, client_address = self.server_socket.accept()
                self.client_socket = client_socket
                self.client_address = client_address
                self.client_connected = True

                self._safe_status(f"İstemci bağlı: {client_address}", "green")
                self._safe_display(f"İstemci bağlandı: {client_address}")

                threading.Thread(target=self._listen_for_messages, daemon=True).start()

            except Exception as e:
                self._safe_display(f"Sunucu hatası: {e}")
                self._safe_status("Hata", "red")

        threading.Thread(target=run_server, daemon=True).start()

    def _listen_for_messages(self):
        try:
            while self.client_connected and self.client_socket:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                try:
                    json_str = data.decode("utf-8")

                    # --- 1. RSA HANDSHAKE KONTROLÜ ---
                    if json_str == "PUB_KEY_REQ":
                        pub_key_msg = {
                            "type": "PUB_KEY_RES",
                            "key": self.server_public_key
                        }
                        self.client_socket.send(json.dumps(pub_key_msg).encode('utf-8'))
                        self._safe_display("İstemciye RSA Public Key gönderildi.")
                        continue
                    # ---------------------------------

                    message_data = json.loads(json_str)

                    # Gelen mesajın modunu al (Kütüphane mi Manuel mi?)
                    impl_mode = message_data.get('impl_mode', 'manual')
                    use_lib_for_decrypt = (impl_mode == 'library')

                    # --- 2. HİBRİT DECRYPTION (RSA ile AES Anahtarını Çözme) ---
                    if "encrypted_aes_key" in message_data:
                        try:
                            enc_key_int = message_data["encrypted_aes_key"]

                            # RSA Private Key ile simetrik anahtarı çöz
                            decrypted_session_key = self.rsa_cipher.decrypt(enc_key_int, self.rsa_cipher.private_key)

                            # --- UI GÜNCELLEME (Thread-Safe) ---
                            method = message_data.get("method", "none")

                            def update_ui_safe():
                                # 1. Metodu ComboBox'ta seç
                                if method in ["aes", "des"]:
                                    self.encryption_var.set(method)

                                # 2. Kütüphane modunu (Checkbox) ayarla
                                self.use_lib_var.set(use_lib_for_decrypt)

                                # 3. Arayüzü yeniden oluştur (DİKKAT: Bu işlem kutuları varsayılana sıfırlar!)
                                self._setup_encryption_params()

                                # 4. KRİTİK DÜZELTME: Anahtarı, arayüz oluştuktan SONRA yazıyoruz
                                if method == "aes":
                                    self.aes_key_var.set(decrypted_session_key)
                                elif method == "des":
                                    self.des_key_var.set(decrypted_session_key)

                                # 5. EncryptionManager'ı güncelle
                                self._update_encryption_settings()

                            self.root.after(0, update_ui_safe)
                            # -----------------------------------

                            # params['key'] alanını RSA'dan çıkan anahtarla güncelle
                            if "params" not in message_data:
                                message_data["params"] = {}
                            message_data["params"]["key"] = decrypted_session_key

                            self._safe_display("İstemci (RSA ile Şifrelenmiş Anahtar Geldi)")
                            self._safe_display(f"Çözülen Anahtar: {decrypted_session_key}")
                            self._safe_display(f"İstemci Modu: {impl_mode.upper()}")

                        except Exception as e:
                            self._safe_display(f"RSA Anahtar Çözme Hatası: {e}")

                    # --- 3. ŞİFRELİ MESAJI ÇÖZME ---
                    encrypted_message = message_data.get("message", "")
                    method = message_data.get("method", "none")
                    params = message_data.get("params", {})

                    if method != "none":
                        # Önce gelen şifreli mesajı ekrana bas
                        self._safe_display(f"İstemci (şifreli): {encrypted_message}")
                        try:
                            # Mod bilgisini (use_lib) decrypt fonksiyonuna geçir
                            decrypted = self.encryption_manager.decrypt(
                                encrypted_message,
                                method,
                                use_lib=use_lib_for_decrypt,
                                **params
                            )
                            # Sonra çözülmüş halini ekrana bas
                            self._safe_display(f"İstemci (çözüldü): {decrypted}")
                        except Exception as e:
                            self._safe_display(f"İstemci (şifre çözme hatası): {e}")
                    else:
                        self._safe_display(f"İstemci: {encrypted_message}")

                except json.JSONDecodeError:
                    message = data.decode("utf-8")
                    self._safe_display(f"İstemci (düz): {message}")

        except Exception as e:
            if self.client_connected:
                self._safe_display(f"Bağlantı hatası: {e}")
        finally:
            if self.client_socket:
                self.client_socket.close()
            self.client_connected = False
            self._safe_status("İstemci bağlantısı kapandı", "red")


    def send_message(self, event=None):
        if not self.client_connected or not self.client_socket:
            messagebox.showerror("Hata", "Bağlı istemci yok!")
            return

        message = self.message_entry.get().strip()
        if not message:
            return

        try:
            self._update_encryption_settings()
            self._safe_display(f"Sunucu (gönderilen): {message}")

            use_lib = self.use_lib_var.get()
            mode_str = "library" if use_lib else "manual"

            if self.current_encryption != "none":
                encrypted_message = self.encryption_manager.encrypt(
                    message,
                    self.current_encryption,
                    use_lib=use_lib,  # <-- Eklendi
                    **self.encryption_params,
                )
                self._safe_display(f"Sunucu ({mode_str}): {encrypted_message}")
            else:
                encrypted_message = message

            message_data = {
                "message": encrypted_message,
                "method": self.current_encryption,
                "params": self.encryption_params,
                "impl_mode": mode_str  # <-- Eklendi
            }

            self.client_socket.send(json.dumps(message_data).encode("utf-8"))
            self.message_entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("Hata", f"Mesaj gönderme hatası: {e}")

    # ------------- Helpers -------------
    def _safe_display(self, message: str):
        def append():
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, message + "\n")
            self.chat_display.config(state=tk.DISABLED)
            self.chat_display.see(tk.END)

        self.root.after(0, append)

    def _safe_status(self, text: str, color: str):
        def update():
            self.status_label.config(text=text, foreground=color)

        self.root.after(0, update)

    def on_closing(self):
        self.client_connected = False
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = ServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()







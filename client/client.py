import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import json
import sys
import os
from time import perf_counter

# Üst dizini path'e ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryption.ciphers import EncryptionManager
from encryption.rsa import RSACipher
from encryption.ecc import ECCCipher


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Şifreli İstemci")
        self.root.geometry("1200x900")
        self.root.configure(bg='#f5f5f5')

        self.client_socket = None
        self.connected = False
        self.host = '127.0.0.1'
        self.port = 8001

        # Sunucu Anahtarları
        self.server_rsa_pub = None
        self.server_ecc_pub = None
        
        # ECC Key Çifti (sadece manuel)
        self.client_ecc = None

        self.encryption_manager = EncryptionManager()

        # GÜVENLİK GÜNCELLEMESİ: Son kullanılan oturum anahtarını hafızada tut
        self.current_session_key = None

        # UI Değişkenleri
        self.selected_method = None
        self.method_buttons = {}
        
        # Performans kayıtları
        self.performance_log = []

        self.setup_ui()
        self.connect_to_server()

    def setup_ui(self):
        """Modern sidebar tabanlı arayüz oluşturur"""
        # Ana container
        main_container = tk.Frame(self.root, bg='#f5f5f5')
        main_container.pack(fill=tk.BOTH, expand=True)

        # Sol Sidebar
        sidebar = tk.Frame(main_container, bg='#2c3e50', width=250)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=0, pady=0)
        sidebar.pack_propagate(False)

        # Sidebar başlık
        title_label = tk.Label(
            sidebar, 
            text="Şifreleme\nYöntemleri", 
            bg='#2c3e50', 
            fg='#ecf0f1',
            font=('Segoe UI', 16, 'bold'),
            pady=20
        )
        title_label.pack()

        # Yöntem listesi
        methods = [
            ("none", "Şifreleme Yok"),
            ("caesar", "Caesar"),
            ("vigenere", "Vigenère"),
            ("substitution", "Substitution"),
            ("rail_fence", "Rail Fence"),
            ("affine", "Affine"),
            ("route", "Route"),
            ("columnar_transposition", "Columnar"),
            ("polybius", "Polybius"),
            ("pigpen", "Pigpen"),
            ("hill", "Hill"),
            ("aes_manual", "AES-128 (Manuel)"),
            ("aes_lib", "AES-128 (Kütüphane)"),
            ("aes_rsa_manual", "AES-128 + RSA (Manuel)"),
            ("aes_rsa_lib", "AES-128 + RSA (Kütüphane)"),
            ("aes_ecc_manual", "AES-128 + ECC (Manuel)"),
            ("des_manual", "DES (Manuel)"),
            ("des_lib", "DES (Kütüphane)"),
            ("des_rsa_manual", "DES + RSA (Manuel)"),
            ("des_rsa_lib", "DES + RSA (Kütüphane)"),
            ("des_ecc_manual", "DES + ECC (Manuel)")
        ]

        # Scrollable frame for methods
        # Container frame for canvas and scrollbar
        scroll_container = tk.Frame(sidebar, bg='#2c3e50')
        scroll_container.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        canvas = tk.Canvas(scroll_container, bg='#2c3e50', highlightthickness=0)
        scrollbar = ttk.Scrollbar(scroll_container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#2c3e50')

        def update_scrollregion(event=None):
            canvas.update_idletasks()
            canvas.configure(scrollregion=canvas.bbox("all"))
            # Canvas window genişliğini ayarla
            canvas_width = canvas.winfo_width()
            if canvas_width > 1:
                canvas.itemconfig(canvas_window, width=canvas_width)

        def on_canvas_configure(event):
            canvas_width = event.width
            canvas.itemconfig(canvas_window, width=canvas_width)

        scrollable_frame.bind("<Configure>", update_scrollregion)
        canvas.bind('<Configure>', on_canvas_configure)

        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Mouse wheel desteği (Windows ve Linux uyumlu)
        def on_mousewheel(event):
            try:
                # Windows
                if hasattr(event, 'delta'):
                    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
                # Linux
                elif event.num == 4:
                    canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    canvas.yview_scroll(1, "units")
            except:
                pass
        
        def bind_to_mousewheel(event):
            canvas.bind_all("<MouseWheel>", on_mousewheel)
            canvas.bind_all("<Button-4>", on_mousewheel)
            canvas.bind_all("<Button-5>", on_mousewheel)
        
        def unbind_from_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")
        
        canvas.bind('<Enter>', bind_to_mousewheel)
        canvas.bind('<Leave>', unbind_from_mousewheel)

        for method_id, method_name in methods:
            btn = tk.Button(
                scrollable_frame,
                text=method_name,
                font=('Segoe UI', 11),
                bg='#34495e',
                fg='#ecf0f1',
                activebackground='#3498db',
                activeforeground='#ffffff',
                relief=tk.FLAT,
                padx=15,
                pady=12,
                anchor='w',
                cursor='hand2',
                command=lambda m=method_id: self.select_method(m)
            )
            btn.pack(fill=tk.X, padx=10, pady=3)
            self.method_buttons[method_id] = btn

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # İlk scrollregion güncellemesi
        update_scrollregion()

        # Sağ taraf - Ana içerik alanı
        content_area = tk.Frame(main_container, bg='#ffffff')
        content_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Üst durum çubuğu
        status_frame = tk.Frame(content_area, bg='#ecf0f1', height=50)
        status_frame.pack(fill=tk.X, padx=0, pady=0)
        status_frame.pack_propagate(False)

        status_label = tk.Label(
            status_frame,
            text="Durum:",
            bg='#ecf0f1',
            fg='#2c3e50',
            font=('Segoe UI', 11, 'bold'),
            padx=15
        )
        status_label.pack(side=tk.LEFT)

        self.status_label = tk.Label(
            status_frame,
            text="Bağlanıyor...",
            bg='#ecf0f1',
            fg='#e67e22',
            font=('Segoe UI', 11),
            padx=5
        )
        self.status_label.pack(side=tk.LEFT)

        # Parametreler alanı
        self.params_container = tk.Frame(content_area, bg='#ffffff')
        self.params_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Varsayılan mesaj
        self.default_label = tk.Label(
            self.params_container,
            text="Lütfen sol taraftan bir şifreleme yöntemi seçin",
            bg='#ffffff',
            fg='#7f8c8d',
            font=('Segoe UI', 14),
            pady=50
        )
        self.default_label.pack()

        # Performans Logu
        perf_frame = tk.LabelFrame(
            content_area,
            text="Performans Logu",
            bg='#ffffff',
            fg='#2c3e50',
            font=('Segoe UI', 11, 'bold'),
            padx=15,
            pady=10
        )
        perf_frame.pack(fill=tk.X, padx=20, pady=10)

        self.perf_display = scrolledtext.ScrolledText(
            perf_frame,
            height=4,
            state=tk.DISABLED,
            font=('Consolas', 10),
            bg='#f8f9fa',
            fg='#2c3e50',
            relief=tk.FLAT,
            borderwidth=0
        )
        self.perf_display.pack(fill=tk.X, padx=5, pady=5)

        # İletişim Logu
        chat_frame = tk.LabelFrame(
            content_area,
            text="İletişim Logu",
            bg='#ffffff',
            fg='#2c3e50',
            font=('Segoe UI', 11, 'bold'),
            padx=15,
            pady=10
        )
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            height=15,
            state=tk.DISABLED,
            font=('Consolas', 10),
            bg='#ffffff',
            fg='#2c3e50',
            relief=tk.FLAT,
            borderwidth=0,
            wrap=tk.WORD
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Mesaj giriş alanı
        input_frame = tk.Frame(content_area, bg='#ecf0f1')
        input_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=20, pady=15)

        self.msg_entry = tk.Entry(
            input_frame,
            font=('Segoe UI', 12),
            relief=tk.FLAT,
            borderwidth=2,
            highlightthickness=1,
            highlightbackground='#bdc3c7',
            highlightcolor='#3498db'
        )
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.msg_entry.bind('<Return>', self.send_message)

        send_btn = tk.Button(
            input_frame,
            text="Gönder",
            font=('Segoe UI', 11, 'bold'),
            bg='#3498db',
            fg='#ffffff',
            activebackground='#2980b9',
            activeforeground='#ffffff',
            relief=tk.FLAT,
            padx=25,
            pady=8,
            cursor='hand2',
            command=self.send_message
        )
        send_btn.pack(side=tk.RIGHT)

    def select_method(self, method_id):
        """Yöntem seçildiğinde çağrılır"""
        # Önceki seçimi temizle
        for btn in self.method_buttons.values():
            btn.config(bg='#34495e', fg='#ecf0f1')
        
        # Yeni seçimi vurgula
        if method_id in self.method_buttons:
            self.method_buttons[method_id].config(bg='#3498db', fg='#ffffff')
        
        self.selected_method = method_id
        
        # Parametre alanını güncelle
        self.setup_params_ui()

    def parse_selection(self):
        """Seçilen yöntemi ayrıştırır"""
        if not self.selected_method:
            return None, False, False, False
        
        method_id = self.selected_method
        
        # AES/DES kontrolü
        if method_id.startswith('aes'):
            method = "aes"
        elif method_id.startswith('des'):
            method = "des"
        else:
            method = method_id
        
        use_lib = "_lib" in method_id or "(Kütüphane)" in method_id
        use_rsa = "_rsa" in method_id or "+ RSA" in method_id
        use_ecc = "_ecc" in method_id or "+ ECC" in method_id
        
        return method, use_lib, use_rsa, use_ecc

    def setup_params_ui(self):
        """Seçilen yönteme göre parametre alanını oluşturur"""
        # Mevcut widget'ları temizle
        for widget in self.params_container.winfo_children():
            widget.destroy()
        
        if not self.selected_method:
            self.default_label = tk.Label(
                self.params_container,
                text="Lütfen sol taraftan bir şifreleme yöntemi seçin",
                bg='#ffffff',
                fg='#7f8c8d',
                font=('Segoe UI', 14),
                pady=50
            )
            self.default_label.pack()
            return
        
        method, use_lib, use_rsa, use_ecc = self.parse_selection()
        
        # Başlık
        title_label = tk.Label(
            self.params_container,
            text=f"Yöntem: {self.method_buttons[self.selected_method].cget('text')}",
            bg='#ffffff',
            fg='#2c3e50',
            font=('Segoe UI', 14, 'bold'),
            pady=10
        )
        title_label.pack(anchor='w')

        # Parametreler frame
        params_frame = tk.Frame(self.params_container, bg='#ffffff')
        params_frame.pack(fill=tk.X, pady=10)

        if method in ["aes", "des"]:
            # AES/DES anahtarı gösterimi
            key_len = 16 if method == "aes" else 8
            key_label = tk.Label(
                params_frame,
                text=f"{method.upper()} Oturum Anahtarı ({key_len} byte):",
                bg='#ffffff',
                fg='#2c3e50',
                font=('Segoe UI', 11),
                padx=10
            )
            key_label.pack(side=tk.LEFT)
            
            self.key_entry_var = tk.StringVar(value="(Otomatik Üretilecek)")
            key_entry = tk.Entry(
                params_frame,
                textvariable=self.key_entry_var,
                state="readonly",
                font=('Consolas', 10),
                width=50,
                relief=tk.FLAT,
                bg='#f8f9fa',
                fg='#2c3e50'
            )
            key_entry.pack(side=tk.LEFT, padx=5)
            
            # RSA key frame
            if use_rsa:
                rsa_frame = tk.Frame(self.params_container, bg='#ffffff')
                rsa_frame.pack(fill=tk.X, pady=5)
                
                rsa_label = tk.Label(
                    rsa_frame,
                    text="RSA Public Key (e,n):",
                    bg='#ffffff',
                    fg='#2c3e50',
                    font=('Segoe UI', 11),
                    padx=10
                )
                rsa_label.pack(side=tk.LEFT)
                
                self.rsa_pub_key_entry = tk.Entry(
                    rsa_frame,
                    font=('Consolas', 10),
                    width=50,
                    relief=tk.FLAT,
                    bg='#ffffff',
                    fg='#2c3e50',
                    highlightthickness=1,
                    highlightbackground='#bdc3c7',
                    highlightcolor='#3498db'
                )
                self.rsa_pub_key_entry.pack(side=tk.LEFT, padx=5)
                
                rsa_btn = tk.Button(
                    rsa_frame,
                    text="Sunucudan Al",
                    font=('Segoe UI', 10),
                    bg='#27ae60',
                    fg='#ffffff',
                    activebackground='#229954',
                    relief=tk.FLAT,
                    padx=15,
                    pady=5,
                    cursor='hand2',
                    command=self.load_server_public_key
                )
                rsa_btn.pack(side=tk.LEFT, padx=5)
            else:
                if hasattr(self, 'rsa_pub_key_entry'):
                    delattr(self, 'rsa_pub_key_entry')
            
            # ECC key frame
            if use_ecc:
                ecc_frame = tk.Frame(self.params_container, bg='#ffffff')
                ecc_frame.pack(fill=tk.X, pady=5)
                
                ecc_label = tk.Label(
                    ecc_frame,
                    text="ECC Public Key (x,y):",
                    bg='#ffffff',
                    fg='#2c3e50',
                    font=('Segoe UI', 11),
                    padx=10
                )
                ecc_label.pack(side=tk.LEFT)
                
                self.ecc_pub_key_entry = tk.Entry(
                    ecc_frame,
                    font=('Consolas', 10),
                    width=50,
                    relief=tk.FLAT,
                    bg='#ffffff',
                    fg='#2c3e50',
                    highlightthickness=1,
                    highlightbackground='#bdc3c7',
                    highlightcolor='#3498db'
                )
                self.ecc_pub_key_entry.pack(side=tk.LEFT, padx=5)
                
                ecc_btn = tk.Button(
                    ecc_frame,
                    text="Sunucudan Al",
                    font=('Segoe UI', 10),
                    bg='#27ae60',
                    fg='#ffffff',
                    activebackground='#229954',
                    relief=tk.FLAT,
                    padx=15,
                    pady=5,
                    cursor='hand2',
                    command=self.load_server_ecc_public_key
                )
                ecc_btn.pack(side=tk.LEFT, padx=5)
            else:
                if hasattr(self, 'ecc_pub_key_entry'):
                    delattr(self, 'ecc_pub_key_entry')
                    
        elif method == "caesar":
            shift_label = tk.Label(
                params_frame,
                text="Shift (Kaydırma):",
                bg='#ffffff',
                fg='#2c3e50',
                font=('Segoe UI', 11),
                padx=10
            )
            shift_label.pack(side=tk.LEFT)
            
            self.shift_var = tk.StringVar(value="3")
            shift_entry = tk.Entry(
                params_frame,
                textvariable=self.shift_var,
                font=('Segoe UI', 11),
                width=10,
                relief=tk.FLAT,
                bg='#ffffff',
                fg='#2c3e50',
                highlightthickness=1,
                highlightbackground='#bdc3c7',
                highlightcolor='#3498db'
            )
            shift_entry.pack(side=tk.LEFT, padx=5)
            
        elif method == "vigenere":
            key_label = tk.Label(
                params_frame,
                text="Anahtar Kelime:",
                bg='#ffffff',
                fg='#2c3e50',
                font=('Segoe UI', 11),
                padx=10
            )
            key_label.pack(side=tk.LEFT)
            
            self.vigenere_key_var = tk.StringVar(value="KEY")
            key_entry = tk.Entry(
                params_frame,
                textvariable=self.vigenere_key_var,
                font=('Segoe UI', 11),
                width=20,
                relief=tk.FLAT,
                bg='#ffffff',
                fg='#2c3e50',
                highlightthickness=1,
                highlightbackground='#bdc3c7',
                highlightcolor='#3498db'
            )
            key_entry.pack(side=tk.LEFT, padx=5)
            
        elif method == "affine":
            a_label = tk.Label(
                params_frame,
                text="a:",
                bg='#ffffff',
                fg='#2c3e50',
                font=('Segoe UI', 11),
                padx=10
            )
            a_label.pack(side=tk.LEFT)
            
            self.aff_a = tk.StringVar(value="5")
            a_entry = tk.Entry(
                params_frame,
                textvariable=self.aff_a,
                font=('Segoe UI', 11),
                width=10,
                relief=tk.FLAT,
                bg='#ffffff',
                fg='#2c3e50',
                highlightthickness=1,
                highlightbackground='#bdc3c7',
                highlightcolor='#3498db'
            )
            a_entry.pack(side=tk.LEFT, padx=5)
            
            b_label = tk.Label(
                params_frame,
                text="b:",
                bg='#ffffff',
                fg='#2c3e50',
                font=('Segoe UI', 11),
                padx=10
            )
            b_label.pack(side=tk.LEFT)
            
            self.aff_b = tk.StringVar(value="8")
            b_entry = tk.Entry(
                params_frame,
                textvariable=self.aff_b,
                font=('Segoe UI', 11),
                width=10,
                relief=tk.FLAT,
                bg='#ffffff',
                fg='#2c3e50',
                highlightthickness=1,
                highlightbackground='#bdc3c7',
                highlightcolor='#3498db'
            )
            b_entry.pack(side=tk.LEFT, padx=5)
            
        elif method == "rail_fence":
            rails_label = tk.Label(
                params_frame,
                text="Ray Sayısı:",
                bg='#ffffff',
                fg='#2c3e50',
                font=('Segoe UI', 11),
                padx=10
            )
            rails_label.pack(side=tk.LEFT)
            
            self.rails_var = tk.StringVar(value="3")
            rails_entry = tk.Entry(
                params_frame,
                textvariable=self.rails_var,
                font=('Segoe UI', 11),
                width=10,
                relief=tk.FLAT,
                bg='#ffffff',
                fg='#2c3e50',
                highlightthickness=1,
                highlightbackground='#bdc3c7',
                highlightcolor='#3498db'
            )
            rails_entry.pack(side=tk.LEFT, padx=5)
            
        elif method == "columnar_transposition":
            col_label = tk.Label(
                params_frame,
                text="Anahtar:",
                bg='#ffffff',
                fg='#2c3e50',
                font=('Segoe UI', 11),
                padx=10
            )
            col_label.pack(side=tk.LEFT)
            
            self.col_key_var = tk.StringVar(value="KEY")
            col_entry = tk.Entry(
                params_frame,
                textvariable=self.col_key_var,
                font=('Segoe UI', 11),
                width=20,
                relief=tk.FLAT,
                bg='#ffffff',
                fg='#2c3e50',
                highlightthickness=1,
                highlightbackground='#bdc3c7',
                highlightcolor='#3498db'
            )
            col_entry.pack(side=tk.LEFT, padx=5)

    def load_server_public_key(self):
        """Sunucudan RSA public key'i yükler"""
        if self.server_rsa_pub:
            e, n = self.server_rsa_pub
            if hasattr(self, 'rsa_pub_key_entry'):
                self.rsa_pub_key_entry.delete(0, tk.END)
                self.rsa_pub_key_entry.insert(0, f"({e}, {n})")
            messagebox.showinfo("Başarılı", "Sunucu RSA public key'i yüklendi.")
        else:
            messagebox.showerror("Hata", "Sunucuya bağlı değil veya RSA public key alınamadı.")
    
    def load_server_ecc_public_key(self):
        """Sunucudan ECC public key'i yükler"""
        if self.server_ecc_pub:
            x, y = self.server_ecc_pub
            if hasattr(self, 'ecc_pub_key_entry'):
                self.ecc_pub_key_entry.delete(0, tk.END)
                self.ecc_pub_key_entry.insert(0, f"({x}, {y})")
            messagebox.showinfo("Başarılı", "Sunucu ECC public key'i yüklendi.")
        else:
            messagebox.showerror("Hata", "Sunucuya bağlı değil veya ECC public key alınamadı.")
    
    def get_rsa_public_key(self, require_manual=False):
        """RSA public key'i alır"""
        if not hasattr(self, 'rsa_pub_key_entry'):
            return None
            
        key_text = self.rsa_pub_key_entry.get().strip()
        if key_text:
            try:
                key_text = key_text.strip('()')
                parts = key_text.split(',')
                if len(parts) == 2:
                    e = int(parts[0].strip())
                    n = int(parts[1].strip())
                    return (e, n)
            except (ValueError, AttributeError):
                pass
        
        if require_manual:
            return None
        
        if self.server_rsa_pub:
            return self.server_rsa_pub
        
        return None
    
    def get_ecc_public_key(self, require_manual=False):
        """ECC public key'i alır"""
        if not hasattr(self, 'ecc_pub_key_entry'):
            return None
            
        key_text = self.ecc_pub_key_entry.get().strip()
        if key_text:
            try:
                key_text = key_text.strip('()')
                parts = key_text.split(',')
                if len(parts) == 2:
                    x = int(parts[0].strip())
                    y = int(parts[1].strip())
                    return (x, y)
            except (ValueError, AttributeError):
                pass
        
        if require_manual:
            return None
        
        if self.server_ecc_pub:
            return self.server_ecc_pub
        
        return None

    def get_ui_params(self):
        """Arayüzden girilen parametreleri toplar"""
        method, use_lib, use_rsa, use_ecc = self.parse_selection()
        if method is None:
            return {}
            
        params = {}
        try:
            if method == "caesar" and hasattr(self, 'shift_var'):
                params["shift"] = int(self.shift_var.get())
            elif method == "vigenere" and hasattr(self, 'vigenere_key_var'):
                params["key"] = self.vigenere_key_var.get()
            elif method == "affine" and hasattr(self, 'aff_a'):
                params["a"] = int(self.aff_a.get())
                params["b"] = int(self.aff_b.get())
            elif method == "rail_fence" and hasattr(self, 'rails_var'):
                params["rails"] = int(self.rails_var.get())
            elif method == "columnar_transposition" and hasattr(self, 'col_key_var'):
                params["key"] = self.col_key_var.get()
        except (ValueError, AttributeError):
            pass
        return params

    def log_output(self, sender, method, key, raw_cipher, plain, is_self=False, encrypt_time=None):
        """Formatlı Loglama"""
        self.chat_display.config(state=tk.NORMAL)

        cipher_show = str(raw_cipher)
        if len(cipher_show) > 50: cipher_show = cipher_show[:50] + "..."

        text_block = (
            f"\nYöntem: {method}\n"
            f"Oturum Anahtarı: {key}\n"
        )
        if encrypt_time is not None:
            text_block += f"Şifreleme Süresi: {encrypt_time*1000:.2f} ms\n"
        text_block += (
            f"{sender} ({method.split(' ')[0]}): {cipher_show}\n"
            f"{sender} (çözüldü): {plain}\n"
            f"{'-' * 40}"
        )

        self.chat_display.insert(tk.END, text_block + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def log_performance(self, method, encrypt_time, message_length):
        """Performans logunu günceller"""
        self.performance_log.append({
            'method': method,
            'time': encrypt_time,
            'length': message_length
        })
        
        # Son 10 kaydı göster
        self.perf_display.config(state=tk.NORMAL)
        self.perf_display.delete(1.0, tk.END)
        
        for entry in self.performance_log[-10:]:
            time_ms = entry['time'] * 1000
            if time_ms < 0.01:
                time_str = f"{time_ms * 1000:.3f} μs"
            else:
                time_str = f"{time_ms:.2f} ms"
            self.perf_display.insert(tk.END, 
                f"{entry['method']}: {time_str} (Mesaj: {entry['length']} karakter)\n")
        
        self.perf_display.config(state=tk.DISABLED)

    def connect_to_server(self):
        def run():
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((self.host, self.port))

                # Handshake
                self.client_socket.send("PUB_KEY_REQ".encode('utf-8'))
                resp = self.client_socket.recv(8192)
                data = json.loads(resp.decode('utf-8'))

                self.server_rsa_pub = tuple(data["rsa_pub"]) if "rsa_pub" in data else None
                self.server_ecc_pub = tuple(data["ecc_pub"]) if "ecc_pub" in data else None

                self.connected = True
                self.root.after(0, lambda: self.status_label.config(text="Bağlandı", fg='#27ae60'))
                self.listen()
            except Exception as e:
                self.root.after(0, lambda: self.status_label.config(text="Hata", fg='#e74c3c'))

        threading.Thread(target=run, daemon=True).start()

    def listen(self):
        while self.connected:
            try:
                data = self.client_socket.recv(8192)
                if not data: break

                msg_data = json.loads(data.decode('utf-8'))
                method = msg_data.get('method')
                impl_mode = msg_data.get('impl_mode', 'manual')
                enc_msg = msg_data.get('message')
                params = msg_data.get('params', {})
                use_rsa = msg_data.get('use_rsa', False)
                use_ecc = msg_data.get('use_ecc', False)
                key_dist = msg_data.get('key_dist', 'NONE')

                session_key = "Bilinmiyor"
                decrypted_msg = ""

                # AES/DES için oturum anahtarını al
                if method in ["aes", "des"]:
                    if use_ecc and 'ecc_public_key' in msg_data:
                        ecc_pub_key = tuple(msg_data['ecc_public_key'])
                        key_len = 16 if method == "aes" else 8
                        
                        if self.client_ecc:
                            shared_secret = self.client_ecc.generate_shared_secret(ecc_pub_key)
                            session_key_bytes = shared_secret[:key_len]
                            self.current_session_key = session_key_bytes
                            params['key'] = session_key_bytes
                            session_key = session_key_bytes.hex()
                        else:
                            session_key = "ECC Key bulunamadı"
                    elif self.current_session_key:
                        session_key_bytes = self.current_session_key
                        params['key'] = session_key_bytes
                        session_key = session_key_bytes.hex()
                    else:
                        session_key = "Bilinmiyor"

                # Mesajı Çöz
                use_lib = (impl_mode == 'library')
                decrypt_start = perf_counter()

                if method in ['aes', 'des']:
                    try:
                        decrypted_msg = self.encryption_manager.decrypt(enc_msg, method, use_lib=use_lib, **params)
                    except Exception as e:
                        decrypted_msg = f"Hata: {e}"
                elif method != 'none':
                    try:
                        decrypted_msg = self.encryption_manager.decrypt(enc_msg, method, use_lib=use_lib, **params)
                    except Exception as e:
                        decrypted_msg = f"Hata: {e}"
                else:
                    decrypted_msg = enc_msg

                decrypt_time = perf_counter() - decrypt_start

                # Ekrana Bas
                if method in ['aes', 'des']:
                    mode_txt = f"{method.upper()} ({impl_mode})"
                    if use_rsa:
                        mode_txt += " + RSA"
                    elif use_ecc:
                        mode_txt += " + ECC"
                else:
                    mode_txt = method

                self.root.after(0, lambda: self.log_output(
                    "Sunucu", mode_txt, session_key if method in ['aes', 'des'] else "-", enc_msg, decrypted_msg, is_self=False, encrypt_time=decrypt_time
                ))

            except Exception:
                self.connected = False
                break

    def send_message(self, event=None):
        if not self.connected: return
        if not self.selected_method:
            messagebox.showwarning("Uyarı", "Lütfen bir şifreleme yöntemi seçin.")
            return
            
        msg = self.msg_entry.get().strip()
        if not msg: return

        method, use_lib, use_rsa, use_ecc = self.parse_selection()
        if method is None:
            return
            
        mode_str = "library" if use_lib else "manual"

        session_key = "-"
        final_payload = {}
        params = {}
        encrypt_time = 0

        try:
            # AES veya DES şifreleme
            if method in ["aes", "des"]:
                key_len = 16 if method == "aes" else 8
                
                if use_rsa:
                    rsa_pub_key = self.get_rsa_public_key(require_manual=True)
                    if not rsa_pub_key:
                        messagebox.showerror("Hata", "RSA Public Key bulunamadı!\n\nRSA şifreleme için public key'i MANUEL olarak girmeniz veya 'Sunucudan Al' butonunu kullanmanız gerekmektedir.")
                        return
                    
                    session_key_bytes = os.urandom(key_len)
                    self.current_session_key = session_key_bytes
                    
                    rsa_start = perf_counter()
                    enc_session_key = RSACipher.encrypt(session_key_bytes, rsa_pub_key)
                    rsa_time = perf_counter() - rsa_start
                    final_payload['encrypted_key'] = enc_session_key
                    final_payload['key_dist'] = 'RSA'
                    final_payload['use_rsa'] = True
                elif use_ecc:
                    if use_lib:
                        messagebox.showerror("Hata", "ECC sadece manuel şifreleme modunda kullanılabilir!")
                        return
                    
                    ecc_pub_key = self.get_ecc_public_key(require_manual=True)
                    if not ecc_pub_key:
                        messagebox.showerror("Hata", "ECC Public Key bulunamadı!")
                        return
                    
                    ecc_start = perf_counter()
                    if not self.client_ecc:
                        self.client_ecc = ECCCipher()
                    client_ecc_pub = self.client_ecc.public_key
                    shared_secret = self.client_ecc.generate_shared_secret(ecc_pub_key)
                    
                    ecc_time = perf_counter() - ecc_start
                    
                    session_key_bytes = shared_secret[:key_len]
                    self.current_session_key = session_key_bytes
                    
                    final_payload['ecc_public_key'] = client_ecc_pub
                    final_payload['key_dist'] = 'ECC'
                    final_payload['use_ecc'] = True
                else:
                    session_key_bytes = os.urandom(key_len)
                    self.current_session_key = session_key_bytes
                    import base64
                    final_payload['session_key'] = base64.b64encode(session_key_bytes).decode('utf-8')
                    final_payload['key_dist'] = 'NONE'
                    final_payload['use_rsa'] = False
                    final_payload['use_ecc'] = False
                
                params = {"key": session_key_bytes}
                encrypt_start = perf_counter()
                enc_msg = self.encryption_manager.encrypt(msg, method, use_lib=use_lib, **params)
                encrypt_time = perf_counter() - encrypt_start
                
                if use_rsa:
                    encrypt_time += rsa_time
                elif use_ecc:
                    encrypt_time += ecc_time
                
                enc_msg_display = enc_msg
                
                payload_params = params.copy()
                if 'key' in payload_params:
                    del payload_params['key']

                final_payload.update({
                    'message': enc_msg,
                    'method': method,
                    'impl_mode': mode_str,
                    'params': payload_params
                })
                
                if hasattr(self, 'key_entry_var'):
                    self.key_entry_var.set(session_key_bytes.hex())
            else:
                params = self.get_ui_params()
                
                encrypt_start = perf_counter()
                if method != "none":
                    enc_msg = self.encryption_manager.encrypt(msg, method, use_lib=use_lib, **params)
                else:
                    enc_msg = msg
                encrypt_time = perf_counter() - encrypt_start
                
                enc_msg_display = enc_msg
                final_payload = {
                    'message': enc_msg,
                    'method': method,
                    'impl_mode': mode_str,
                    'params': params,
                    'use_rsa': False
                }

            # GÖNDER VE LOGLA
            self.client_socket.send(json.dumps(final_payload).encode('utf-8'))

            # Log için anahtar gösterimi
            if method in ['aes', 'des']:
                disp_method = f"{method.upper()} ({mode_str})"
                if use_rsa:
                    disp_method += " + RSA"
                if 'session_key_bytes' in locals():
                    session_key_display = session_key_bytes.hex()
                else:
                    session_key_display = "-"
            else:
                disp_method = method
                session_key_display = "-"
            
            self.log_output("Sen", disp_method, session_key_display, enc_msg_display, msg, is_self=True, encrypt_time=encrypt_time)
            self.log_performance(disp_method, encrypt_time, len(msg))

            self.msg_entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("Hata", f"Gönderim Hatası: {e}")


def main():
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

import json
import os
import socket
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from time import perf_counter

# Üst dizini (encryption klasörünü bulabilmesi için) path'e ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryption.ciphers import EncryptionManager
from encryption.rsa import RSACipher
from encryption.ecc import ECCCipher


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Şifreli Sunucu")
        self.root.geometry("1200x900")
        self.root.configure(bg='#f5f5f5')

        self.host = '127.0.0.1'
        self.port = 8001
        self.server_socket = None
        self.client_socket = None
        self.connected = False
        self.running = True

        self.enc_manager = EncryptionManager()

        # UI Değişkenleri
        self.selected_method = None
        self.method_buttons = {}
        self.status_var = tk.StringVar(value="Başlatılıyor...")
        
        # Performans kayıtları
        self.performance_log = []
        
        # Oturum anahtarı
        self.current_session_key = None
        
        # Substitution key saklama (mesajdan geldiğinde)
        self.saved_substitution_key = ""

        # 2. LOGLAMA VE KRİPTOGRAFİK KURULUM (ÖNCE RSA OLUŞTUR)
        self.rsa = RSACipher(key_size=1024)
        
        # ECC Key Çifti - Başlangıçta üret (manuel mod için)
        self.server_ecc = ECCCipher()

        # 1. ARAYÜZÜ OLUŞTUR
        self.setup_ui()

        self.log_gui("Sistem başlatılıyor...")
        self.log_gui("RSA Anahtar Çifti (1024-bit) üretildi.")
        self.log_gui(f"RSA Public Key: {self.rsa.public_key}")
        self.log_gui("ECC Anahtar Çifti (P-256) üretildi.")
        self.log_gui(f"ECC Public Key: {self.server_ecc.public_key}")

        # Sunucuyu Başlat
        threading.Thread(target=self.start_server, daemon=True).start()

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
            textvariable=self.status_var,
            bg='#ecf0f1',
            fg='#e67e22',
            font=('Segoe UI', 11),
            padx=5
        )
        self.status_label.pack(side=tk.LEFT)

        port_label = tk.Label(
            status_frame,
            text=f"({self.host}:{self.port})",
            bg='#ecf0f1',
            fg='#7f8c8d',
            font=('Segoe UI', 10),
            padx=15
        )
        port_label.pack(side=tk.RIGHT)

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
        self.msg_entry.bind("<Return>", self.send_message)

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
        
        use_lib = "_lib" in method_id
        use_rsa = "_rsa" in method_id
        use_ecc = "_ecc" in method_id
        
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
            # AES/DES anahtarı girişi
            key_len = 16 if method == "aes" else 8
            
            key_label = tk.Label(
                params_frame,
                text=f"{method.upper()} Anahtarı ({key_len} karakter):",
                bg='#ffffff',
                fg='#2c3e50',
                font=('Segoe UI', 11),
                padx=10
            )
            key_label.pack(side=tk.LEFT)
            
            self.key_var = tk.StringVar(value="")
            key_entry = tk.Entry(
                params_frame,
                textvariable=self.key_var,
                font=('Consolas', 10),
                width=50,
                relief=tk.FLAT,
                bg='#ffffff',
                fg='#2c3e50',
                highlightthickness=1,
                highlightbackground='#bdc3c7',
                highlightcolor='#3498db'
            )
            key_entry.pack(side=tk.LEFT, padx=5)
            
            # Placeholder text
            key_entry.insert(0, f"Boş bırakılırsa otomatik üretilir ({key_len} karakter)")
            key_entry.config(fg='#95a5a6')
            
            def on_key_entry_focus_in(event):
                if key_entry.get() == f"Boş bırakılırsa otomatik üretilir ({key_len} karakter)":
                    key_entry.delete(0, tk.END)
                    key_entry.config(fg='#2c3e50')
            
            def on_key_entry_focus_out(event):
                if not key_entry.get().strip():
                    key_entry.insert(0, f"Boş bırakılırsa otomatik üretilir ({key_len} karakter)")
                    key_entry.config(fg='#95a5a6')
            
            key_entry.bind('<FocusIn>', on_key_entry_focus_in)
            key_entry.bind('<FocusOut>', on_key_entry_focus_out)
            
            # Otomatik üret butonu
            gen_key_btn = tk.Button(
                params_frame,
                text="Otomatik Üret",
                font=('Segoe UI', 10),
                bg='#27ae60',
                fg='#ffffff',
                activebackground='#229954',
                relief=tk.FLAT,
                padx=15,
                pady=5,
                cursor='hand2',
                command=lambda: self.generate_key(method)
            )
            gen_key_btn.pack(side=tk.LEFT, padx=5)
            
            # RSA key frame
            if use_rsa:
                rsa_frame = tk.Frame(self.params_container, bg='#ffffff')
                rsa_frame.pack(fill=tk.X, pady=5)
                
                rsa_label = tk.Label(
                    rsa_frame,
                    text="RSA Private Key (d,n):",
                    bg='#ffffff',
                    fg='#2c3e50',
                    font=('Segoe UI', 11),
                    padx=10
                )
                rsa_label.pack(side=tk.LEFT)
                
                self.rsa_priv_key_entry = tk.Entry(
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
                self.rsa_priv_key_entry.pack(side=tk.LEFT, padx=5)
                
                rsa_btn = tk.Button(
                    rsa_frame,
                    text="Otomatik Doldur",
                    font=('Segoe UI', 10),
                    bg='#27ae60',
                    fg='#ffffff',
                    activebackground='#229954',
                    relief=tk.FLAT,
                    padx=15,
                    pady=5,
                    cursor='hand2',
                    command=self.fill_rsa_private_key
                )
                rsa_btn.pack(side=tk.LEFT, padx=5)
            else:
                if hasattr(self, 'rsa_priv_key_entry'):
                    delattr(self, 'rsa_priv_key_entry')
            
            # ECC key frame
            if use_ecc:
                ecc_frame = tk.Frame(self.params_container, bg='#ffffff')
                ecc_frame.pack(fill=tk.X, pady=5)
                
                ecc_label = tk.Label(
                    ecc_frame,
                    text="ECC Private Key:",
                    bg='#ffffff',
                    fg='#2c3e50',
                    font=('Segoe UI', 11),
                    padx=10
                )
                ecc_label.pack(side=tk.LEFT)
                
                self.ecc_priv_key_entry = tk.Entry(
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
                self.ecc_priv_key_entry.pack(side=tk.LEFT, padx=5)
                
                ecc_btn = tk.Button(
                    ecc_frame,
                    text="Otomatik Doldur",
                    font=('Segoe UI', 10),
                    bg='#27ae60',
                    fg='#ffffff',
                    activebackground='#229954',
                    relief=tk.FLAT,
                    padx=15,
                    pady=5,
                    cursor='hand2',
                    command=self.fill_ecc_private_key
                )
                ecc_btn.pack(side=tk.LEFT, padx=5)
            else:
                if hasattr(self, 'ecc_priv_key_entry'):
                    delattr(self, 'ecc_priv_key_entry')
                    
        elif method == "caesar":
            shift_label = tk.Label(
                params_frame,
                text="Shift:",
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
            
        elif method == "substitution":
            key_label = tk.Label(
                params_frame,
                text="Substitution Key (26 harf):",
                bg='#ffffff',
                fg='#2c3e50',
                font=('Segoe UI', 11),
                padx=10
            )
            key_label.pack(side=tk.LEFT)
            
            # Eğer daha önce bir key saklanmışsa onu kullan
            saved_key = getattr(self, 'saved_substitution_key', "")
            self.substitution_key_var = tk.StringVar(value=saved_key)
            key_entry = tk.Entry(
                params_frame,
                textvariable=self.substitution_key_var,
                font=('Consolas', 10),
                width=30,
                relief=tk.FLAT,
                bg='#ffffff',
                fg='#2c3e50',
                highlightthickness=1,
                highlightbackground='#bdc3c7',
                highlightcolor='#3498db'
            )
            key_entry.pack(side=tk.LEFT, padx=5)
            
            # Eğer key varsa normal, yoksa placeholder
            if saved_key:
                key_entry.config(fg='#2c3e50', state='normal')
            else:
                # Placeholder text
                key_entry.insert(0, "Mesajdan otomatik alınacak")
                key_entry.config(fg='#95a5a6', state='readonly')
            
        elif method == "hill":
            matrix_label = tk.Label(
                params_frame,
                text="Key Matrix (örn: [[3,3],[2,5]]):",
                bg='#ffffff',
                fg='#2c3e50',
                font=('Segoe UI', 11),
                padx=10
            )
            matrix_label.pack(side=tk.LEFT)
            
            self.hill_matrix_var = tk.StringVar(value="[[3,3],[2,5]]")
            matrix_entry = tk.Entry(
                params_frame,
                textvariable=self.hill_matrix_var,
                font=('Consolas', 10),
                width=30,
                relief=tk.FLAT,
                bg='#ffffff',
                fg='#2c3e50',
                highlightthickness=1,
                highlightbackground='#bdc3c7',
                highlightcolor='#3498db'
            )
            matrix_entry.pack(side=tk.LEFT, padx=5)
            
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

    def update_status(self, text, color):
        """Durum çubuğunu güvenli şekilde günceller"""
        self.root.after(0, lambda: [
            self.status_var.set(text),
            self.status_label.config(fg=color)
        ])

    def log_gui(self, text):
        self.root.after(0, lambda: self._append_text(f"[SİSTEM]: {text}\n"))

    def log_transaction(self, sender, method, key, cipher, plain, encrypt_time=None):
        cipher_show = str(cipher)
        if len(cipher_show) > 50: cipher_show = cipher_show[:50] + "..."
        msg = (
            f"\nYöntem: {method}\n"
            f"Oturum Anahtarı: {key}\n"
        )
        if encrypt_time is not None:
            msg += f"Şifreleme Süresi: {encrypt_time*1000:.2f} ms\n"
        msg += (
            f"{sender} ({method.split(' ')[0]}): {cipher_show}\n"
            f"{sender} (çözüldü): {plain}\n"
            f"{'-' * 40}\n"
        )
        self.root.after(0, lambda: self._append_text(msg))
    
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
            self.update_status("İstemci Bekleniyor... (Dinleniyor)", "#3498db")
            self.log_gui(f"Sunucu {self.port} portunda dinlemeye başladı.")

            client, addr = self.server_socket.accept()
            self.client_socket = client
            self.connected = True

            self.update_status(f"Bağlandı: {addr[0]}", "#27ae60")
            self.log_gui(f"İstemci bağlandı: {addr}")

            self.listen()
        except Exception as e:
            self.update_status("Hata Oluştu", "#e74c3c")
            self.log_gui(f"Sunucu Başlatma Hatası: {e}")

    def listen(self):
        while self.connected:
            try:
                data = self.client_socket.recv(8192)
                if not data: break

                txt = data.decode('utf-8')

                if txt == "PUB_KEY_REQ":
                    resp = {
                        "rsa_pub": self.rsa.public_key,
                        "ecc_pub": self.server_ecc.public_key if self.server_ecc else None
                    }
                    self.client_socket.send(json.dumps(resp).encode('utf-8'))
                    self.log_gui("RSA ve ECC Public Key'ler gönderildi.")
                    continue

                self.process_incoming_message(json.loads(txt))
            except Exception as e:
                self.log_gui(f"Bağlantı hatası: {e}")
                break

        self.connected = False
        self.update_status("Bağlantı Kesildi", "#e74c3c")

    def process_incoming_message(self, data):
        method = data.get('method')
        impl_mode = data.get('impl_mode', 'manual')
        enc_msg = data.get('message')
        use_rsa = data.get('use_rsa', False)
        use_ecc = data.get('use_ecc', False)
        key_dist = data.get('key_dist', 'NONE')
        params = data.get('params', {})

        session_key = "Yok"
        decrypted_msg = ""
        decrypt_time = 0

        # 1. Anahtarı Çöz (AES veya DES için)
        if method in ["aes", "des"]:
            session_key_bytes = None
            
            if use_rsa and 'encrypted_key' in data:
                decrypt_key_start = perf_counter()
                private_key = self.get_rsa_private_key(require_manual=False)
                if not private_key:
                    self.log_gui("HATA: RSA Private Key bulunamadı!")
                    return
                
                key_text = self.rsa_priv_key_entry.get().strip() if hasattr(self, 'rsa_priv_key_entry') else ""
                if not key_text:
                    self.log_gui("UYARI: Otomatik üretilen RSA Private Key kullanılıyor.")
                
                session_key_bytes = self.rsa.decrypt(data['encrypted_key'], private_key)
                decrypt_key_time = perf_counter() - decrypt_key_start
                
                key_len = 16 if method == "aes" else 8
                # Bytes'ı string'e çevir
                try:
                    session_key_str = session_key_bytes.decode('utf-8', errors='ignore')
                    if len(session_key_str) != key_len:
                        if len(session_key_str) > key_len:
                            session_key_str = session_key_str[:key_len]
                        else:
                            import string
                            import random
                            session_key_str = session_key_str + ''.join(random.choices(string.ascii_letters + string.digits, k=key_len - len(session_key_str)))
                    session_key_bytes = session_key_str.encode('utf-8')
                except:
                    import string
                    import random
                    session_key_str = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
                    session_key_bytes = session_key_str.encode('utf-8')
                
                self.log_gui(f"RSA ile şifrelenmiş anahtar çözüldü ({decrypt_key_time*1000:.2f} ms, {len(session_key_str)} karakter)")
            elif use_ecc and 'ecc_public_key' in data and 'encrypted_key' in data:
                use_lib = (impl_mode == 'library')
                if use_lib:
                    self.log_gui("HATA: ECC sadece manuel şifreleme modunda kullanılabilir!")
                    return
                
                client_ecc_pub = tuple(data['ecc_public_key'])
                self.log_gui(f"İstemciden ECC Public Key alındı: {client_ecc_pub}")
                
                # ECC ile şifrelenmiş key'i çöz
                key_len = 16 if method == "aes" else 8
                
                ecc_start = perf_counter()
                shared_secret = self.server_ecc.generate_shared_secret(client_ecc_pub)
                ecc_time = perf_counter() - ecc_start
                
                # Şifrelenmiş key'i hex'den bytes'a çevir
                encrypted_key_hex = data['encrypted_key']
                encrypted_key_bytes = bytes.fromhex(encrypted_key_hex)
                
                # ECC shared secret ile XOR yaparak çöz
                ecc_key = shared_secret[:len(encrypted_key_bytes)]
                session_key_bytes = bytes(a ^ b for a, b in zip(encrypted_key_bytes, ecc_key))
                
                # Key uzunluğunu kontrol et
                if len(session_key_bytes) != key_len:
                    self.log_gui(f"UYARI: Key uzunluğu beklenen ({key_len}) ile uyuşmuyor ({len(session_key_bytes)}). Düzeltiliyor...")
                    if len(session_key_bytes) > key_len:
                        session_key_bytes = session_key_bytes[:key_len]
                    else:
                        session_key_bytes = session_key_bytes + b'\x00' * (key_len - len(session_key_bytes))
                
                self.log_gui(f"ECC ile şifrelenmiş anahtar çözüldü ({ecc_time*1000:.2f} ms, {len(session_key_bytes)} byte)")
            elif 'session_key' in data:
                # Artık session_key direkt string olarak geliyor
                session_key_str = data['session_key']
                if isinstance(session_key_str, str):
                    key_len = 16 if method == "aes" else 8
                    if len(session_key_str) != key_len:
                        self.log_gui(f"UYARI: Anahtar uzunluğu beklenen ({key_len}) ile uyuşmuyor ({len(session_key_str)}). Düzeltiliyor...")
                        if len(session_key_str) > key_len:
                            session_key_str = session_key_str[:key_len]
                        else:
                            import string
                            import random
                            session_key_str = session_key_str + ''.join(random.choices(string.ascii_letters + string.digits, k=key_len - len(session_key_str)))
                    session_key_bytes = session_key_str.encode('utf-8')
                    self.log_gui(f"Oturum anahtarı alındı (RSA olmadan, {len(session_key_str)} karakter)")
                else:
                    self.log_gui(f"HATA: Oturum anahtarı string formatında değil!")
                    return
            elif self.current_session_key:
                # Mevcut key'i string'e çevir
                try:
                    session_key_str = self.current_session_key.decode('utf-8', errors='ignore')
                    key_len = 16 if method == "aes" else 8
                    if len(session_key_str) != key_len:
                        import string
                        import random
                        session_key_str = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
                    session_key_bytes = self.current_session_key
                    self.log_gui("Önceki oturum anahtarı kullanılıyor")
                except:
                    import string
                    import random
                    key_len = 16 if method == "aes" else 8
                    session_key_str = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
                    session_key_bytes = session_key_str.encode('utf-8')
            elif 'key' in params:
                # Params'tan key al
                if isinstance(params['key'], str):
                    session_key_str = params['key']
                    session_key_bytes = session_key_str.encode('utf-8')
                else:
                    session_key_bytes = params['key']
                    try:
                        session_key_str = session_key_bytes.decode('utf-8', errors='ignore')
                    except:
                        import string
                        import random
                        key_len = 16 if method == "aes" else 8
                        session_key_str = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
                        session_key_bytes = session_key_str.encode('utf-8')
                self.log_gui("Params'tan anahtar alındı")
            else:
                self.log_gui("HATA: Oturum anahtarı bulunamadı!")
                return
            
            key_len = 16 if method == "aes" else 8
            
            # ECC kullanılıyorsa da key'i string'e çevir (ECC sadece key exchange için, key normal AES/DES key'i)
            if use_ecc:
                # ECC ile çözülen key'i string'e çevir
                if isinstance(session_key_bytes, bytes):
                    try:
                        session_key_str = session_key_bytes.decode('utf-8', errors='ignore')
                        if len(session_key_str) != key_len:
                            self.log_gui(f"UYARI: Anahtar uzunluğu beklenen ({key_len}) ile uyuşmuyor ({len(session_key_str)}). Düzeltiliyor...")
                            if len(session_key_str) > key_len:
                                session_key_str = session_key_str[:key_len]
                            else:
                                import string
                                import random
                                session_key_str = session_key_str + ''.join(random.choices(string.ascii_letters + string.digits, k=key_len - len(session_key_str)))
                            session_key_bytes = session_key_str.encode('utf-8')
                    except:
                        import string
                        import random
                        session_key_str = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
                        session_key_bytes = session_key_str.encode('utf-8')
                else:
                    session_key_str = session_key_bytes
                
                if session_key_str:
                    self.current_session_key = session_key_bytes if isinstance(session_key_bytes, bytes) else session_key_str.encode('utf-8')
                    params['key'] = session_key_str
                else:
                    self.log_gui("HATA: session_key None!")
                    return
            else:
                # Diğer durumlarda string formatına çevir
                if isinstance(session_key_bytes, bytes):
                    try:
                        session_key_str = session_key_bytes.decode('utf-8', errors='ignore')
                        if len(session_key_str) != key_len:
                            self.log_gui(f"UYARI: Anahtar uzunluğu beklenen ({key_len}) ile uyuşmuyor ({len(session_key_str)}). Düzeltiliyor...")
                            if len(session_key_str) > key_len:
                                session_key_str = session_key_str[:key_len]
                            else:
                                import string
                                import random
                                session_key_str = session_key_str + ''.join(random.choices(string.ascii_letters + string.digits, k=key_len - len(session_key_str)))
                            session_key_bytes = session_key_str.encode('utf-8')
                    except:
                        import string
                        import random
                        session_key_str = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
                        session_key_bytes = session_key_str.encode('utf-8')
                else:
                    session_key_str = session_key_bytes

                if session_key_str:
                    self.current_session_key = session_key_bytes if isinstance(session_key_bytes, bytes) else session_key_str.encode('utf-8')
                    params['key'] = session_key_str
                else:
                    self.log_gui("HATA: session_key None!")
                    return

            # UI güncelle
            combo_val = method.upper()
            if impl_mode == "library":
                combo_val += " (Kütüphane)"
            else:
                combo_val += " (Manuel)"
            if use_rsa:
                combo_val += " + RSA"
            elif use_ecc:
                combo_val += " + ECC"

            def update_ui_safe():
                # Method ID'yi bul
                method_map = {
                    "aes": "aes_manual" if impl_mode == "manual" else "aes_lib",
                    "des": "des_manual" if impl_mode == "manual" else "des_lib"
                }
                if use_rsa:
                    method_map["aes"] = "aes_rsa_manual" if impl_mode == "manual" else "aes_rsa_lib"
                    method_map["des"] = "des_rsa_manual" if impl_mode == "manual" else "des_rsa_lib"
                elif use_ecc:
                    method_map["aes"] = "aes_ecc_manual"
                    method_map["des"] = "des_ecc_manual"
                
                method_id = method_map.get(method, method)
                if method_id in self.method_buttons:
                    self.select_method(method_id)
                if hasattr(self, 'key_var'): 
                    # Key'i UI'da göster, ama sadece eğer boşsa
                    current_key = self.key_var.get().strip()
                    if not current_key or current_key.startswith("Boş bırakılırsa"):
                        # Key'i string olarak göster (ECC sadece key exchange için, key normal AES/DES key'i)
                        session_key_display = session_key_str if 'session_key_str' in locals() else (session_key_bytes.decode('utf-8', errors='ignore') if isinstance(session_key_bytes, bytes) else str(session_key_bytes))
                        self.key_var.set(session_key_display)
                        # Entry widget'ı bul ve rengi düzelt
                        for widget in self.params_container.winfo_children():
                            if isinstance(widget, tk.Frame):
                                for child in widget.winfo_children():
                                    if isinstance(child, tk.Entry) and child.cget('textvariable') == str(self.key_var):
                                        child.config(fg='#2c3e50')
                                        break

            self.root.after(0, update_ui_safe)
        else:
            def update_ui_safe():
                if method in self.method_buttons:
                    self.select_method(method)
                
                # Substitution için key kontrolü ve UI güncelleme
                if method == "substitution" and 'key' in params:
                    # Key'i instance variable'da sakla
                    self.saved_substitution_key = params['key']
                    # UI'ı yeniden oluştur (key ile birlikte)
                    if method in self.method_buttons:
                        self.select_method(method)
                
                # Hill için key_matrix kontrolü ve UI güncelleme
                if method == "hill" and 'key_matrix' in params:
                    if hasattr(self, 'hill_matrix_var'):
                        self.hill_matrix_var.set(str(params['key_matrix']))
                
                # Affine için a ve b UI güncelleme
                if method == "affine":
                    if 'a' in params and hasattr(self, 'aff_a'):
                        self.aff_a.set(str(params['a']))
                    if 'b' in params and hasattr(self, 'aff_b'):
                        self.aff_b.set(str(params['b']))

            self.root.after(0, update_ui_safe)

        # 3. Mesajı Çöz
        try:
            use_lib = (impl_mode == 'library')
            
            # Substitution için key kontrolü
            if method == "substitution":
                if 'key' not in params:
                    self.log_gui("HATA: Substitution cipher için key gerekli!")
                    return
            
            decrypt_start = perf_counter()
            
            if method in ['aes', 'des']:
                decrypted_msg = self.enc_manager.decrypt(enc_msg, method, use_lib=use_lib, **params)
            elif method != 'none':
                decrypted_msg = self.enc_manager.decrypt(enc_msg, method, use_lib=use_lib, **params)
            else:
                decrypted_msg = enc_msg

            decrypt_time = perf_counter() - decrypt_start

            if method in ['aes', 'des']:
                mode_display = f"{method.upper()} ({impl_mode})"
                if use_rsa:
                    mode_display += " + RSA"
                elif use_ecc:
                    mode_display += " + ECC"
                # Key'i string olarak göster (ECC sadece key exchange için)
                session_key_display = session_key_str if 'session_key_str' in locals() else (session_key_bytes.decode('utf-8', errors='ignore') if 'session_key_bytes' in locals() and isinstance(session_key_bytes, bytes) else "Yok")
            else:
                mode_display = method
                session_key_display = "-"

            self.log_transaction("İstemci", mode_display, session_key_display, enc_msg, decrypted_msg, encrypt_time=decrypt_time)
            self.log_performance(mode_display, decrypt_time, len(decrypted_msg))

        except Exception as e:
            self.log_gui(f"Şifre çözme hatası: {e}")

    def fill_rsa_private_key(self):
        """RSA private key'i otomatik doldurur"""
        if self.rsa and self.rsa.private_key:
            d, n = self.rsa.private_key
            if hasattr(self, 'rsa_priv_key_entry'):
                self.rsa_priv_key_entry.delete(0, tk.END)
                self.rsa_priv_key_entry.insert(0, f"({d}, {n})")
            self.log_gui("RSA Private Key otomatik dolduruldu.")
    
    def fill_ecc_private_key(self):
        """ECC private key'i otomatik doldurur"""
        if self.server_ecc:
            priv_key = self.server_ecc.private_key
            if hasattr(self, 'ecc_priv_key_entry'):
                self.ecc_priv_key_entry.delete(0, tk.END)
                self.ecc_priv_key_entry.insert(0, str(priv_key))
            self.log_gui("ECC Private Key otomatik dolduruldu.")
        else:
            self.log_gui("ECC Private Key bulunamadı.")
    
    def generate_key(self, method):
        """AES veya DES için otomatik key üretir"""
        key_len = 16 if method == "aes" else 8
        # Rastgele karakterlerden oluşan string üret
        import string
        import random
        key_string = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
        
        if hasattr(self, 'key_var'):
            self.key_var.set(key_string)
            # Entry widget'ı bul ve rengi düzelt
            for widget in self.params_container.winfo_children():
                if isinstance(widget, tk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, tk.Entry) and child.cget('textvariable') == str(self.key_var):
                            child.config(fg='#2c3e50')
                            break
    
    def get_aes_des_key(self, method):
        """AES veya DES key'ini UI'dan alır veya otomatik üretir"""
        key_len = 16 if method == "aes" else 8
        
        if hasattr(self, 'key_var'):
            key_text = self.key_var.get().strip()
            # Placeholder text kontrolü
            if key_text and not key_text.startswith("Boş bırakılırsa"):
                if len(key_text) != key_len:
                    self.log_gui(f"HATA: {method.upper()} anahtarı tam olarak {key_len} karakter olmalıdır!")
                    return None
                # String'i direkt kullan (bytes'a çevirme, _derive_key yapacak)
                return key_text
        
        # Key girilmemişse otomatik üret
        import string
        import random
        key_string = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
        if hasattr(self, 'key_var'):
            self.key_var.set(key_string)
        return key_string
    
    def get_rsa_private_key(self, require_manual=False):
        """RSA private key'i alır"""
        if hasattr(self, 'rsa_priv_key_entry'):
            key_text = self.rsa_priv_key_entry.get().strip()
            if key_text:
                try:
                    key_text = key_text.strip('()')
                    parts = key_text.split(',')
                    if len(parts) == 2:
                        d = int(parts[0].strip())
                        n = int(parts[1].strip())
                        return (d, n)
                except (ValueError, AttributeError):
                    pass
        
        if require_manual:
            return None
        
        if self.rsa and self.rsa.private_key:
            return self.rsa.private_key
        
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
            elif method == "substitution":
                # Önce params'tan key'i al (eğer varsa - mesajdan geldiyse)
                # Eğer params'ta yoksa UI'dan al
                if 'key' not in params and hasattr(self, 'substitution_key_var'):
                    key = self.substitution_key_var.get().strip()
                    # Placeholder text kontrolü
                    if key and not key.startswith("Mesajdan otomatik"):
                        params["key"] = key.upper()
                elif 'key' not in params:
                    # Key yoksa hata
                    messagebox.showerror("Hata", "Substitution cipher için key gerekli!")
                    return
            elif method == "hill" and hasattr(self, 'hill_matrix_var'):
                matrix_str = self.hill_matrix_var.get().strip()
                if matrix_str:
                    try:
                        # String'i list'e çevir
                        import ast
                        params["key_matrix"] = ast.literal_eval(matrix_str)
                    except:
                        pass  # Varsayılan matrix kullanılacak
        except (ValueError, AttributeError):
            pass
        return params

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
        params = {}
        encrypt_time = 0

        try:
            # AES/DES için oturum anahtarı kontrolü
            if method in ["aes", "des"]:
                # Önce UI'dan key al, yoksa current_session_key kullan, o da yoksa otomatik üret
                key_string = None
                
                # 1. UI'dan key al
                if hasattr(self, 'key_var'):
                    key_text = self.key_var.get().strip()
                    if key_text and not key_text.startswith("Boş bırakılırsa"):
                        key_len = 16 if method == "aes" else 8
                        if len(key_text) != key_len:
                            messagebox.showerror("Hata", f"{method.upper()} anahtarı tam olarak {key_len} karakter olmalıdır!")
                            return
                        key_string = key_text
                
                # 2. UI'da key yoksa, current_session_key kullan
                if key_string is None and self.current_session_key:
                    try:
                        key_string = self.current_session_key.decode('utf-8', errors='ignore')
                        key_len = 16 if method == "aes" else 8
                        if len(key_string) != key_len:
                            import string
                            import random
                            key_string = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
                        if hasattr(self, 'key_var'):
                            self.key_var.set(key_string)
                    except:
                        import string
                        import random
                        key_len = 16 if method == "aes" else 8
                        key_string = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
                        if hasattr(self, 'key_var'):
                            self.key_var.set(key_string)
                
                # 3. Hiçbiri yoksa otomatik üret
                if key_string is None:
                    key_len = 16 if method == "aes" else 8
                    import string
                    import random
                    key_string = ''.join(random.choices(string.ascii_letters + string.digits, k=key_len))
                    if hasattr(self, 'key_var'):
                        self.key_var.set(key_string)
                
                params["key"] = key_string
                self.current_session_key = key_string.encode('utf-8')
            else:
                params = self.get_ui_params()

            # Şifrele
            encrypt_start = perf_counter()
            if method in ["aes", "des"]:
                enc_msg = self.enc_manager.encrypt(msg, method, use_lib=use_lib, **params)
            elif method != "none":
                enc_msg = self.enc_manager.encrypt(msg, method, use_lib=use_lib, **params)
            else:
                enc_msg = msg
            encrypt_time = perf_counter() - encrypt_start

            # GÜVENLİK: AES/DES anahtarlarını pakete koyma (Substitution, Hill vb. için key gönderilmeli)
            payload_params = params.copy()
            if method in ["aes", "des"] and 'key' in payload_params:
                del payload_params['key']

            # Gönder
            payload = {
                'message': enc_msg,
                'method': method,
                'params': payload_params,
                'impl_mode': mode_str,
                'use_rsa': use_rsa if method in ["aes", "des"] else False,
                'use_ecc': use_ecc if method in ["aes", "des"] else False,
                'key_dist': 'RSA' if use_rsa else ('ECC' if use_ecc else 'NONE')
            }

            self.client_socket.send(json.dumps(payload).encode('utf-8'))

            # Logla
            if method in ['aes', 'des']:
                disp_method = f"{method.upper()} ({mode_str})"
                if use_rsa:
                    disp_method += " + RSA"
                elif use_ecc:
                    disp_method += " + ECC"
                key_display = key_string if 'key_string' in locals() else "-"
            else:
                disp_method = method
                key_display = "-"
            
            self.log_transaction("Sunucu", disp_method, key_display, enc_msg, msg, encrypt_time=encrypt_time)
            self.log_performance(disp_method, encrypt_time, len(msg))
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

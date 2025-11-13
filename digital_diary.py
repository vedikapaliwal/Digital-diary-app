import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, colorchooser, filedialog
import json
import hashlib
import os
from datetime import datetime
import sqlite3
import base64

class DigitalDiaryPro:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Digital Diary Pro - Complete Features")
        self.root.geometry("900x700")
        self.center_window(self.root)
        
        # Current settings
        self.current_user = None
        self.current_font_size = 12
        self.current_font_family = "Arial"
        self.current_theme = "light"
        self.text_color = "black"
        
        # Database setup
        self.setup_database()
        
        # Data files
        self.users_file = "users_pro.json"
        self.settings_file = "settings_pro.json"
        
        # Initialize data files
        self.initialize_data_files()
        
        # Start with welcome screen
        self.show_welcome_screen()

    def setup_database(self):
        """Setup SQLite database for enhanced features"""
        self.conn = sqlite3.connect('diary_pro.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                title TEXT,
                content TEXT,
                category TEXT,
                mood TEXT,
                tags TEXT,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                date TEXT,
                word_count INTEGER,
                mood TEXT,
                writing_time INTEGER
            )
        ''')
        
        self.conn.commit()

    def initialize_data_files(self):
        """Create necessary data files"""
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump({}, f)
        
        if not os.path.exists(self.settings_file):
            with open(self.settings_file, 'w') as f:
                json.dump({}, f)

    def center_window(self, window):
        """Center the window on screen"""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')

    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def encrypt_data(self, data):
        """Simple encryption using base64"""
        return base64.b64encode(data.encode()).decode()

    def decrypt_data(self, encrypted_data):
        """Simple decryption using base64"""
        return base64.b64decode(encrypted_data.encode()).decode()

    def clear_window(self):
        """Clear all widgets from current window"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_welcome_screen(self):
        """Enhanced welcome screen"""
        self.clear_window()
        self.current_user = None
        
        # Create gradient background
        canvas = tk.Canvas(self.root, width=900, height=700, highlightthickness=0)
        canvas.pack(fill=tk.BOTH, expand=True)
        
        # Simple gradient effect
        colors = ['#e3f2fd', '#bbdefb', '#90caf9', '#64b5f6']
        for i in range(700):
            color_index = min(i // 175, len(colors) - 1)
            color = colors[color_index]
            canvas.create_line(0, i, 900, i, fill=color)
        
        main_frame = ttk.Frame(canvas, padding="40")
        main_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # Title with better styling
        title_label = ttk.Label(main_frame, text="📖 Digital Diary Pro", 
                               font=("Arial", 28, "bold"), foreground="#2c3e50")
        title_label.grid(row=0, column=0, pady=(0, 10))
        
        subtitle_label = ttk.Label(main_frame, text="Your Complete Personal Journal Solution", 
                                  font=("Arial", 12), foreground="#7f8c8d")
        subtitle_label.grid(row=1, column=0, pady=(0, 40))
        
        # Feature highlights
        features = [
            "🔐 Secure Password Protection",
            "📊 Writing Statistics & Analytics", 
            "🎨 Rich Text Editor with Formatting",
            "🔍 Advanced Search & Filters",
            "📁 Categories & Tags Organization"
        ]
        
        for i, feature in enumerate(features):
            ttk.Label(main_frame, text=feature, font=("Arial", 10)).grid(
                row=2+i, column=0, pady=2)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=8, column=0, pady=30)
        
        login_btn = ttk.Button(button_frame, text="🚪 Login", 
                              command=self.show_login_screen, width=20)
        login_btn.grid(row=0, column=0, pady=10, padx=5)
        
        signup_btn = ttk.Button(button_frame, text="📝 Create New Account", 
                               command=self.show_signup_screen, width=20)
        signup_btn.grid(row=0, column=1, pady=10, padx=5)
        
        exit_btn = ttk.Button(button_frame, text="❌ Exit", 
                             command=self.root.quit, width=20)
        exit_btn.grid(row=0, column=2, pady=10, padx=5)

    def show_login_screen(self):
        """Enhanced login screen with security features"""
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="40")
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        title_label = ttk.Label(main_frame, text="🔐 Secure Login", 
                               font=("Arial", 20, "bold"))
        title_label.grid(row=0, column=0, pady=(0, 30))
        
        # Username
        ttk.Label(main_frame, text="Username:", font=("Arial", 10)).grid(
            row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.username_entry = ttk.Entry(main_frame, width=30, font=("Arial", 10))
        self.username_entry.grid(row=2, column=0, pady=(0, 15))
        self.username_entry.focus()
        
        # Password
        ttk.Label(main_frame, text="Password:", font=("Arial", 10)).grid(
            row=3, column=0, sticky=tk.W, pady=(0, 5))
        self.password_entry = ttk.Entry(main_frame, width=30, show="•", font=("Arial", 10))
        self.password_entry.grid(row=4, column=0, pady=(0, 30))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, pady=10)
        
        login_btn = ttk.Button(button_frame, text="Login", width=15,
                              command=self.perform_login)
        login_btn.grid(row=0, column=0, padx=5)
        
        back_btn = ttk.Button(button_frame, text="Back", width=15,
                             command=self.show_welcome_screen)
        back_btn.grid(row=0, column=1, padx=5)
        
        # Bind Enter key
        self.root.bind('<Return>', lambda e: self.perform_login())

    def perform_login(self):
        """Perform login with security features"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
        except:
            users = {}
        
        hashed_password = self.hash_password(password)
        if username in users and users[username] == hashed_password:
            self.current_user = username
            self.show_main_dashboard()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def show_signup_screen(self):
        """Enhanced signup screen"""
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="40")
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        title_label = ttk.Label(main_frame, text="📝 Create New Account", 
                               font=("Arial", 20, "bold"))
        title_label.grid(row=0, column=0, pady=(0, 30))
        
        # Username
        ttk.Label(main_frame, text="Username:", font=("Arial", 10)).grid(
            row=1, column=0, sticky=tk.W, pady=(0, 5))
        username_entry = ttk.Entry(main_frame, width=30, font=("Arial", 10))
        username_entry.grid(row=2, column=0, pady=(0, 15))
        username_entry.focus()
        
        # Password
        ttk.Label(main_frame, text="Password:", font=("Arial", 10)).grid(
            row=3, column=0, sticky=tk.W, pady=(0, 5))
        password_entry = ttk.Entry(main_frame, width=30, show="•", font=("Arial", 10))
        password_entry.grid(row=4, column=0, pady=(0, 15))
        
        # Confirm Password
        ttk.Label(main_frame, text="Confirm Password:", font=("Arial", 10)).grid(
            row=5, column=0, sticky=tk.W, pady=(0, 5))
        confirm_password_entry = ttk.Entry(main_frame, width=30, show="•", font=("Arial", 10))
        confirm_password_entry.grid(row=6, column=0, pady=(0, 30))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=8, column=0, pady=10)
        
        register_btn = ttk.Button(button_frame, text="Register", width=15,
                                command=lambda: self.register_user(
                                    username_entry.get(), 
                                    password_entry.get(), 
                                    confirm_password_entry.get()))
        register_btn.grid(row=0, column=0, padx=5)
        
        back_btn = ttk.Button(button_frame, text="Back", width=15,
                             command=self.show_welcome_screen)
        back_btn.grid(row=0, column=1, padx=5)
        
        self.root.bind('<Return>', 
                      lambda e: self.register_user(
                          username_entry.get(), 
                          password_entry.get(), 
                          confirm_password_entry.get()))

    def register_user(self, username, password, confirm_password):
        """Enhanced user registration"""
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if len(username) < 3:
            messagebox.showerror("Error", "Username must be at least 3 characters long")
            return
        
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long")
            return
        
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
        except:
            users = {}
        
        if username in users:
            messagebox.showerror("Error", "Username already exists")
            return
        
        hashed_password = self.hash_password(password)
        users[username] = hashed_password
        
        with open(self.users_file, 'w') as f:
            json.dump(users, f)
        
        messagebox.showinfo("Success", "Account created successfully! Please login.")
        self.show_login_screen()

    def show_main_dashboard(self):
        """Main dashboard with all features"""
        self.clear_window()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        # Dashboard Tab
        self.create_dashboard_tab()
        
        # Editor Tab
        self.create_editor_tab()
        
        # Entries Tab
        self.create_entries_tab()
        
        # Statistics Tab
        self.create_statistics_tab()
        
        # Settings Tab
        self.create_settings_tab()

    def create_dashboard_tab(self):
        """Create dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="🏠 Dashboard")
        
        # Welcome section
        welcome_frame = ttk.LabelFrame(dashboard_frame, text="Welcome", padding="15")
        welcome_frame.pack(fill=tk.X, padx=10, pady=5)
        
        welcome_label = ttk.Label(welcome_frame, 
                                 text=f"🎉 Welcome back, {self.current_user}!",
                                 font=("Arial", 16, "bold"))
        welcome_label.pack(anchor=tk.W)
        
        date_label = ttk.Label(welcome_frame, 
                              text=f"📅 Today is {datetime.now().strftime('%A, %B %d, %Y')}",
                              font=("Arial", 11))
        date_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Quick Stats
        stats_frame = ttk.LabelFrame(dashboard_frame, text="📊 Quick Statistics", padding="15")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.stats_labels = {}
        stats_data = [
            ("Total Entries", "0"),
            ("Words Written", "0"),
            ("Writing Streak", "0 days"),
            ("Favorite Category", "None")
        ]
        
        for i, (label, value) in enumerate(stats_data):
            stat_frame = ttk.Frame(stats_frame)
            stat_frame.grid(row=i//2, column=i%2, sticky=tk.W, padx=10, pady=5)
            
            ttk.Label(stat_frame, text=label, font=("Arial", 9)).pack(anchor=tk.W)
            self.stats_labels[label] = ttk.Label(stat_frame, text=value, 
                                               font=("Arial", 12, "bold"))
            self.stats_labels[label].pack(anchor=tk.W)
        
        # Quick Actions
        actions_frame = ttk.LabelFrame(dashboard_frame, text="⚡ Quick Actions", padding="15")
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        actions = [
            ("📝 New Entry", self.show_editor_tab),
            ("🔍 Search Entries", self.show_search_dialog),
            ("📁 View All Entries", self.show_entries_tab),
            ("📊 View Statistics", self.show_statistics_tab)
        ]
        
        for i, (text, command) in enumerate(actions):
            btn = ttk.Button(actions_frame, text=text, command=command)
            btn.grid(row=i//2, column=i%2, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # Recent Entries
        recent_frame = ttk.LabelFrame(dashboard_frame, text="📄 Recent Entries", padding="15")
        recent_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)
        
        self.recent_tree = ttk.Treeview(recent_frame, columns=("Title", "Date", "Category"), show="headings", height=8)
        self.recent_tree.heading("Title", text="Title")
        self.recent_tree.heading("Date", text="Date")
        self.recent_tree.heading("Category", text="Category")
        self.recent_tree.pack(expand=True, fill=tk.BOTH)
        
        # Update dashboard data
        self.update_dashboard_data()

    def create_editor_tab(self):
        """Create rich text editor tab"""
        editor_frame = ttk.Frame(self.notebook)
        self.notebook.add(editor_frame, text="📝 Editor")
        
        # Toolbar
        toolbar = ttk.Frame(editor_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # Title
        ttk.Label(toolbar, text="Title:").grid(row=0, column=0, padx=2)
        self.title_entry = ttk.Entry(toolbar, width=30)
        self.title_entry.grid(row=0, column=1, padx=5)
        
        # Category
        ttk.Label(toolbar, text="Category:").grid(row=0, column=2, padx=(20,2))
        self.category_combo = ttk.Combobox(toolbar, 
                                          values=["Personal", "Work", "Dreams", "Travel", "Ideas", "Goals"],
                                          state="readonly")
        self.category_combo.grid(row=0, column=3, padx=5)
        
        # Mood
        ttk.Label(toolbar, text="Mood:").grid(row=0, column=4, padx=(20,2))
        self.mood_combo = ttk.Combobox(toolbar, 
                                      values=["😊 Happy", "😢 Sad", "😠 Angry", "😴 Tired", "😃 Excited", "😌 Peaceful"],
                                      state="readonly")
        self.mood_combo.grid(row=0, column=5, padx=5)
        
        # Formatting toolbar
        format_toolbar = ttk.Frame(editor_frame)
        format_toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(format_toolbar, text="B", width=3, 
                  command=lambda: self.format_text("bold")).grid(row=0, column=0, padx=1)
        ttk.Button(format_toolbar, text="I", width=3, 
                  command=lambda: self.format_text("italic")).grid(row=0, column=1, padx=1)
        ttk.Button(format_toolbar, text="U", width=3, 
                  command=lambda: self.format_text("underline")).grid(row=0, column=2, padx=1)
        
        ttk.Button(format_toolbar, text="Text Color", 
                  command=self.choose_text_color).grid(row=0, column=3, padx=5)
        
        ttk.Button(format_toolbar, text="Bg Color", 
                  command=self.choose_bg_color).grid(row=0, column=4, padx=5)
        
        # Word count label
        self.word_count_label = ttk.Label(format_toolbar, text="Words: 0")
        self.word_count_label.grid(row=0, column=5, padx=20)
        
        # Text area
        text_frame = ttk.Frame(editor_frame)
        text_frame.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        self.editor_text = scrolledtext.ScrolledText(
            text_frame, wrap=tk.WORD, width=80, height=20,
            font=(self.current_font_family, self.current_font_size), 
            padx=10, pady=10, foreground=self.text_color)
        self.editor_text.pack(expand=True, fill=tk.BOTH)
        self.editor_text.bind('<KeyRelease>', self.update_word_count)
        
        # Action buttons
        button_frame = ttk.Frame(editor_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="💾 Save Entry", 
                  command=self.save_entry).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="🗑️ Clear", 
                  command=self.clear_editor).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="📤 Export", 
                  command=self.export_entry).grid(row=0, column=2, padx=5)

    def create_entries_tab(self):
        """Create entries browser tab"""
        entries_frame = ttk.Frame(self.notebook)
        self.notebook.add(entries_frame, text="📁 Entries")
        
        # Search and filter frame
        search_frame = ttk.Frame(entries_frame)
        search_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=2)
        self.search_entry = ttk.Entry(search_frame, width=30)
        self.search_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(search_frame, text="Category:").grid(row=0, column=2, padx=(20,2))
        self.search_category = ttk.Combobox(search_frame, 
                                           values=["All", "Personal", "Work", "Dreams", "Travel", "Ideas"])
        self.search_category.set("All")
        self.search_category.grid(row=0, column=3, padx=5)
        
        ttk.Button(search_frame, text="🔍 Search", 
                  command=self.search_entries).grid(row=0, column=4, padx=5)
        ttk.Button(search_frame, text="🔄 Refresh", 
                  command=self.load_entries).grid(row=0, column=5, padx=5)
        
        # Entries list
        list_frame = ttk.Frame(entries_frame)
        list_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        self.entries_tree = ttk.Treeview(list_frame, 
                                        columns=("Title", "Date", "Category", "Mood"), 
                                        show="headings", height=15)
        self.entries_tree.heading("Title", text="Title")
        self.entries_tree.heading("Date", text="Date")
        self.entries_tree.heading("Category", text="Category")
        self.entries_tree.heading("Mood", text="Mood")
        
        self.entries_tree.column("Title", width=200)
        self.entries_tree.column("Date", width=120)
        self.entries_tree.column("Category", width=100)
        self.entries_tree.column("Mood", width=80)
        
        self.entries_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.entries_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.entries_tree.configure(yscrollcommand=scrollbar.set)
        
        # Double click to view entry
        self.entries_tree.bind('<Double-1>', self.view_selected_entry)
        
        # Load entries
        self.load_entries()

    def create_statistics_tab(self):
        """Create statistics tab"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="📊 Statistics")
        
        # Statistics content
        content_frame = ttk.Frame(stats_frame, padding="20")
        content_frame.pack(expand=True, fill=tk.BOTH)
        
        # Writing statistics
        writing_frame = ttk.LabelFrame(content_frame, text="📈 Writing Statistics", padding="15")
        writing_frame.pack(fill=tk.X, pady=10)
        
        self.writing_stats_text = scrolledtext.ScrolledText(
            writing_frame, wrap=tk.WORD, width=80, height=10,
            font=("Arial", 10))
        self.writing_stats_text.pack(expand=True, fill=tk.BOTH)
        
        # Mood statistics
        mood_frame = ttk.LabelFrame(content_frame, text="😊 Mood Statistics", padding="15")
        mood_frame.pack(fill=tk.X, pady=10)
        
        self.mood_stats_text = scrolledtext.ScrolledText(
            mood_frame, wrap=tk.WORD, width=80, height=8,
            font=("Arial", 10))
        self.mood_stats_text.pack(expand=True, fill=tk.BOTH)
        
        # Update statistics
        ttk.Button(content_frame, text="🔄 Update Statistics", 
                  command=self.update_statistics_display).pack(pady=10)
        
        self.update_statistics_display()

    def create_settings_tab(self):
        """Create settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        content_frame = ttk.Frame(settings_frame, padding="20")
        content_frame.pack(expand=True, fill=tk.BOTH)
        
        # Appearance settings
        appearance_frame = ttk.LabelFrame(content_frame, text="🎨 Appearance Settings", padding="15")
        appearance_frame.pack(fill=tk.X, pady=10)
        
        # Font Family
        ttk.Label(appearance_frame, text="Font Family:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.font_family_combo = ttk.Combobox(appearance_frame, 
                                            values=["Arial", "Times New Roman", "Courier New", "Verdana", "Georgia"],
                                            state="readonly")
        self.font_family_combo.set(self.current_font_family)
        self.font_family_combo.grid(row=0, column=1, padx=10, pady=5)
        
        # Font Size
        ttk.Label(appearance_frame, text="Font Size:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.font_size_combo = ttk.Combobox(appearance_frame, 
                                          values=["10", "12", "14", "16", "18", "20"],
                                          state="readonly")
        self.font_size_combo.set(str(self.current_font_size))
        self.font_size_combo.grid(row=1, column=1, padx=10, pady=5)
        
        # Text Color
        ttk.Label(appearance_frame, text="Text Color:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.color_display = tk.Label(appearance_frame, text="Sample", 
                                     bg="white", fg=self.text_color, font=("Arial", 10), width=10)
        self.color_display.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)
        
        ttk.Button(appearance_frame, text="Choose Color", 
                  command=self.choose_settings_color).grid(row=2, column=2, padx=5, pady=5)
        
        # Apply settings button
        ttk.Button(appearance_frame, text="💾 Apply Appearance Settings", 
                  command=self.apply_appearance_settings).grid(row=3, column=0, columnspan=3, pady=10)
        
        # Security settings
        security_frame = ttk.LabelFrame(content_frame, text="🔐 Security", padding="15")
        security_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(security_frame, text="Change Password", 
                  command=self.show_change_password).pack(anchor=tk.W, pady=5)
        
        # Data management
        data_frame = ttk.LabelFrame(content_frame, text="💾 Data Management", padding="15")
        data_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(data_frame, text="Export All Data", 
                  command=self.export_all_data).pack(anchor=tk.W, pady=2)
        ttk.Button(data_frame, text="Create Backup", 
                  command=self.create_backup).pack(anchor=tk.W, pady=2)
        
        # Account actions
        account_frame = ttk.LabelFrame(content_frame, text="👤 Account", padding="15")
        account_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(account_frame, text="Logout", 
                  command=self.show_welcome_screen).pack(anchor=tk.W, pady=2)
        ttk.Button(account_frame, text="Exit Application", 
                  command=self.root.quit).pack(anchor=tk.W, pady=2)

    def format_text(self, format_type):
        """Format selected text"""
        try:
            if format_type == "bold":
                current_tags = self.editor_text.tag_names("sel.first")
                if "bold" in current_tags:
                    self.editor_text.tag_remove("bold", "sel.first", "sel.last")
                else:
                    self.editor_text.tag_add("bold", "sel.first", "sel.last")
                    self.editor_text.tag_configure("bold", font=(self.current_font_family, self.current_font_size, "bold"))
            elif format_type == "italic":
                current_tags = self.editor_text.tag_names("sel.first")
                if "italic" in current_tags:
                    self.editor_text.tag_remove("italic", "sel.first", "sel.last")
                else:
                    self.editor_text.tag_add("italic", "sel.first", "sel.last")
                    self.editor_text.tag_configure("italic", font=(self.current_font_family, self.current_font_size, "italic"))
            elif format_type == "underline":
                current_tags = self.editor_text.tag_names("sel.first")
                if "underline" in current_tags:
                    self.editor_text.tag_remove("underline", "sel.first", "sel.last")
                else:
                    self.editor_text.tag_add("underline", "sel.first", "sel.last")
                    self.editor_text.tag_configure("underline", underline=True)
        except tk.TclError:
            pass  # No text selected

    def choose_text_color(self):
        """Choose text color for selected text"""
        color = colorchooser.askcolor(title="Choose text color")[1]
        if color:
            try:
                self.editor_text.tag_add("color", "sel.first", "sel.last")
                self.editor_text.tag_configure("color", foreground=color)
            except tk.TclError:
                # If no text selected, set default color for future text
                self.editor_text.config(foreground=color)
                self.text_color = color

    def choose_bg_color(self):
        """Choose background color for editor"""
        color = colorchooser.askcolor(title="Choose background color")[1]
        if color:
            self.editor_text.config(bg=color)

    def choose_settings_color(self):
        """Choose text color from settings"""
        color = colorchooser.askcolor(title="Choose text color")[1]
        if color:
            self.text_color = color
            self.color_display.config(fg=color)
            # Apply immediately to editor
            self.editor_text.config(foreground=color)

    def apply_appearance_settings(self):
        """Apply all appearance settings"""
        # Update font family
        new_font_family = self.font_family_combo.get()
        if new_font_family:
            self.current_font_family = new_font_family
        
        # Update font size
        new_font_size = self.font_size_combo.get()
        if new_font_size:
            self.current_font_size = int(new_font_size)
        
        # Apply to editor
        self.editor_text.config(
            font=(self.current_font_family, self.current_font_size),
            foreground=self.text_color
        )
        
        messagebox.showinfo("Success", "Appearance settings applied successfully!")

    def update_word_count(self, event=None):
        """Update word count in editor"""
        content = self.editor_text.get(1.0, tk.END)
        words = len(content.split())
        self.word_count_label.config(text=f"Words: {words}")

    def save_entry(self):
        """Save entry to database"""
        title = self.title_entry.get()
        content = self.editor_text.get(1.0, tk.END).strip()
        category = self.category_combo.get()
        mood = self.mood_combo.get()
        
        if not content:
            messagebox.showwarning("Warning", "Cannot save empty entry")
            return
        
        if not title:
            title = f"Entry {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        # Encrypt content
        encrypted_content = self.encrypt_data(content)
        
        try:
            self.cursor.execute('''
                INSERT INTO entries (username, title, content, category, mood, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (self.current_user, title, encrypted_content, category, mood, ""))
            
            self.conn.commit()
            
            # Update statistics
            word_count = len(content.split())
            self.update_statistics(word_count, mood)
            
            messagebox.showinfo("Success", "Entry saved successfully!")
            self.clear_editor()
            self.update_dashboard_data()
            self.load_entries()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save entry: {str(e)}")

    def update_statistics(self, word_count, mood):
        """Update writing statistics"""
        today = datetime.now().strftime("%Y-%m-%d")
        
        self.cursor.execute('''
            INSERT OR REPLACE INTO statistics (username, date, word_count, mood, writing_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (self.current_user, today, word_count, mood, 0))
        
        self.conn.commit()

    def clear_editor(self):
        """Clear the editor"""
        self.title_entry.delete(0, tk.END)
        self.editor_text.delete(1.0, tk.END)
        self.category_combo.set('')
        self.mood_combo.set('')
        self.update_word_count()

    def export_entry(self):
        """Export current entry to file"""
        content = self.editor_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "No content to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export Current Entry"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Title: {self.title_entry.get()}\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
                    f.write(f"Category: {self.category_combo.get()}\n")
                    f.write(f"Mood: {self.mood_combo.get()}\n")
                    f.write("\n" + "="*50 + "\n\n")
                    f.write(content)
                
                messagebox.showinfo("Success", f"Entry exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")

    def load_entries(self):
        """Load entries into the treeview"""
        self.entries_tree.delete(*self.entries_tree.get_children())
        
        try:
            self.cursor.execute('''
                SELECT title, created_date, category, mood FROM entries 
                WHERE username = ? ORDER BY created_date DESC
            ''', (self.current_user,))
            
            for entry in self.cursor.fetchall():
                self.entries_tree.insert("", "end", values=entry)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load entries: {str(e)}")

    def search_entries(self):
        """Search entries based on criteria"""
        query = self.search_entry.get()
        category = self.search_category.get()
        
        self.entries_tree.delete(*self.entries_tree.get_children())
        
        try:
            sql = '''
                SELECT title, created_date, category, mood FROM entries 
                WHERE username = ?
            '''
            params = [self.current_user]
            
            if query:
                sql += " AND (title LIKE ?)"
                params.append(f"%{query}%")
            
            if category != "All":
                sql += " AND category = ?"
                params.append(category)
            
            sql += " ORDER BY created_date DESC"
            
            self.cursor.execute(sql, params)
            
            for entry in self.cursor.fetchall():
                self.entries_tree.insert("", "end", values=entry)
                
        except Exception as e:
            messagebox.showerror("Error", f"Search failed: {str(e)}")

    def view_selected_entry(self, event):
        """View selected entry in editor"""
        selection = self.entries_tree.selection()
        if selection:
            item = self.entries_tree.item(selection[0])
            title = item['values'][0]
            
            try:
                self.cursor.execute('''
                    SELECT title, content, category, mood FROM entries 
                    WHERE username = ? AND title = ?
                ''', (self.current_user, title))
                
                entry = self.cursor.fetchone()
                if entry:
                    # Switch to editor tab
                    self.notebook.select(1)  # Editor tab is index 1
                    
                    # Load entry into editor
                    self.title_entry.delete(0, tk.END)
                    self.title_entry.insert(0, entry[0])
                    
                    self.editor_text.delete(1.0, tk.END)
                    decrypted_content = self.decrypt_data(entry[1])
                    self.editor_text.insert(1.0, decrypted_content)
                    
                    self.category_combo.set(entry[2] if entry[2] else "")
                    self.mood_combo.set(entry[3] if entry[3] else "")
                    
                    self.update_word_count()
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load entry: {str(e)}")

    def update_dashboard_data(self):
        """Update dashboard with current statistics"""
        try:
            # Total entries
            self.cursor.execute('SELECT COUNT(*) FROM entries WHERE username = ?', (self.current_user,))
            total_entries = self.cursor.fetchone()[0]
            self.stats_labels["Total Entries"].config(text=str(total_entries))
            
            # Total words
            self.cursor.execute('SELECT SUM(word_count) FROM statistics WHERE username = ?', (self.current_user,))
            total_words = self.cursor.fetchone()[0] or 0
            self.stats_labels["Words Written"].config(text=str(total_words))
            
            # Recent entries
            self.cursor.execute('''
                SELECT title, created_date, category FROM entries 
                WHERE username = ? ORDER BY created_date DESC LIMIT 10
            ''', (self.current_user,))
            
            self.recent_tree.delete(*self.recent_tree.get_children())
            for entry in self.cursor.fetchall():
                self.recent_tree.insert("", "end", values=entry)
                
        except Exception as e:
            print(f"Error updating dashboard: {e}")

    def update_statistics_display(self):
        """Update statistics display"""
        try:
            # Writing statistics
            self.cursor.execute('''
                SELECT date, SUM(word_count) FROM statistics 
                WHERE username = ? GROUP BY date ORDER BY date DESC LIMIT 30
            ''', (self.current_user,))
            
            writing_stats = "Last 30 Days Writing Statistics:\n\n"
            data = self.cursor.fetchall()
            
            if data:
                for date, word_count in data:
                    writing_stats += f"{date}: {word_count or 0} words\n"
            else:
                writing_stats += "No writing data available yet.\nStart writing to see your statistics!"
            
            self.writing_stats_text.config(state=tk.NORMAL)
            self.writing_stats_text.delete(1.0, tk.END)
            self.writing_stats_text.insert(1.0, writing_stats)
            self.writing_stats_text.config(state=tk.DISABLED)
            
            # Mood statistics
            self.cursor.execute('''
                SELECT mood, COUNT(*) FROM statistics 
                WHERE username = ? AND mood IS NOT NULL GROUP BY mood
            ''', (self.current_user,))
            
            mood_stats = "Mood Distribution:\n\n"
            mood_data = self.cursor.fetchall()
            
            if mood_data:
                total = sum(count for _, count in mood_data)
                for mood, count in mood_data:
                    percentage = (count / total) * 100
                    mood_stats += f"{mood}: {count} times ({percentage:.1f}%)\n"
            else:
                mood_stats += "No mood data available yet.\nAdd moods to your entries to see statistics!"
            
            self.mood_stats_text.config(state=tk.NORMAL)
            self.mood_stats_text.delete(1.0, tk.END)
            self.mood_stats_text.insert(1.0, mood_stats)
            self.mood_stats_text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update statistics: {str(e)}")

    def show_change_password(self):
        """Show change password dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Password")
        dialog.geometry("400x250")
        dialog.transient(self.root)
        dialog.grab_set()
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(main_frame, text="Current Password:").pack(anchor=tk.W, pady=(0,5))
        current_password = ttk.Entry(main_frame, show="•", width=30)
        current_password.pack(fill=tk.X, pady=(0,15))
        
        ttk.Label(main_frame, text="New Password:").pack(anchor=tk.W, pady=(0,5))
        new_password = ttk.Entry(main_frame, show="•", width=30)
        new_password.pack(fill=tk.X, pady=(0,15))
        
        ttk.Label(main_frame, text="Confirm New Password:").pack(anchor=tk.W, pady=(0,5))
        confirm_password = ttk.Entry(main_frame, show="•", width=30)
        confirm_password.pack(fill=tk.X, pady=(0,20))
        
        def change_password():
            current = current_password.get()
            new = new_password.get()
            confirm = confirm_password.get()
            
            if not all([current, new, confirm]):
                messagebox.showerror("Error", "Please fill all fields")
                return
            
            if new != confirm:
                messagebox.showerror("Error", "New passwords don't match")
                return
            
            if len(new) < 6:
                messagebox.showerror("Error", "New password must be at least 6 characters")
                return
            
            try:
                with open(self.users_file, 'r') as f:
                    users = json.load(f)
                
                if users.get(self.current_user) != self.hash_password(current):
                    messagebox.showerror("Error", "Current password is incorrect")
                    return
                
                users[self.current_user] = self.hash_password(new)
                
                with open(self.users_file, 'w') as f:
                    json.dump(users, f)
                
                messagebox.showinfo("Success", "Password changed successfully!")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to change password: {str(e)}")
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Change Password", 
                  command=change_password).pack(side=tk.LEFT, padx=(0,10))
        ttk.Button(button_frame, text="Cancel", 
                  command=dialog.destroy).pack(side=tk.LEFT)

    def export_all_data(self):
        """Export all data to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export All Data"
        )
        
        if filename:
            try:
                self.cursor.execute('''
                    SELECT title, content, category, mood, created_date FROM entries 
                    WHERE username = ? ORDER BY created_date
                ''', (self.current_user,))
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Digital Diary Pro - Complete Export\n")
                    f.write(f"User: {self.current_user}\n")
                    f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*60 + "\n\n")
                    
                    for entry in self.cursor.fetchall():
                        f.write(f"Title: {entry[0]}\n")
                        f.write(f"Date: {entry[4]}\n")
                        f.write(f"Category: {entry[2]}\n")
                        f.write(f"Mood: {entry[3]}\n")
                        f.write(f"Content:\n{self.decrypt_data(entry[1])}\n")
                        f.write("-"*50 + "\n\n")
                
                messagebox.showinfo("Success", f"All data exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")

    def create_backup(self):
        """Create backup of all data"""
        backup_file = f"diary_backup_{self.current_user}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            self.cursor.execute('''
                SELECT title, content, category, mood, created_date 
                FROM entries WHERE username = ?
            ''', (self.current_user,))
            
            entries = []
            for entry in self.cursor.fetchall():
                entries.append({
                    'title': entry[0],
                    'content': self.decrypt_data(entry[1]),
                    'category': entry[2],
                    'mood': entry[3],
                    'date': entry[4]
                })
            
            backup_data = {
                'user': self.current_user,
                'backup_date': datetime.now().isoformat(),
                'entries': entries
            }
            
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("Backup Created", f"Backup saved as {backup_file}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Backup failed: {str(e)}")

    def show_editor_tab(self):
        """Switch to editor tab"""
        self.notebook.select(1)

    def show_entries_tab(self):
        """Switch to entries tab"""
        self.notebook.select(2)

    def show_statistics_tab(self):
        """Switch to statistics tab"""
        self.notebook.select(3)

    def show_search_dialog(self):
        """Show search dialog"""
        self.notebook.select(2)  # Switch to entries tab
        self.search_entry.focus()

    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = DigitalDiaryPro()
    app.run()


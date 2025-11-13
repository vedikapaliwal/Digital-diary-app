import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import hashlib
import os
from datetime import datetime

class DigitalDiaryApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Digital Diary - Multi-User Secure Notes")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        self.center_window(self.root)
        
        # Apply modern theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Data files
        self.users_file = "users.json"
        self.current_user = None
        self.bg_canvas = None
        
        # Initialize data files
        self.initialize_data_files()
        
        # Start with welcome screen
        self.show_welcome_screen()
    
    def center_window(self, window):
        """Center the window on screen"""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_diary_background(self):
        """Create a beautiful light pink background for diary screen"""
        try:
            # Create canvas for background
            self.bg_canvas = tk.Canvas(self.root, width=500, height=400, highlightthickness=0)
            self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
            
            # Create soft light pink gradient background
            colors = ['#ffebee', '#fce4ec', '#f8bbd9', '#f48fb1']
            for i in range(400):
                color_index = min(i // 100, len(colors) - 1)
                color = colors[color_index]
                self.bg_canvas.create_line(0, i, 500, i, fill=color, width=1)
            
            # Add some decorative elements in matching colors
            # Hearts on right side
            self.bg_canvas.create_oval(380, 60, 420, 100, fill='#f8bbd9', outline='#f48fb1')
            self.bg_canvas.create_oval(410, 60, 450, 100, fill='#f8bbd9', outline='#f48fb1')
            self.bg_canvas.create_polygon(380, 80, 450, 80, 415, 120, fill='#f8bbd9', outline='#f48fb1')
            
            # Small hearts on left side
            self.bg_canvas.create_oval(60, 100, 80, 120, fill='#fce4ec', outline='#f8bbd9')
            self.bg_canvas.create_oval(75, 100, 95, 120, fill='#fce4ec', outline='#f8bbd9')
            self.bg_canvas.create_polygon(60, 110, 95, 110, 77, 130, fill='#fce4ec', outline='#f8bbd9')
            
            # Send to background
            self.bg_canvas.lower('all')
            
        except Exception as e:
            print(f"Background creation failed: {e}")
            # Simple fallback - just set light pink background color
            self.root.configure(bg='lightpink')
    
    def initialize_data_files(self):
        """Create users.json if it doesn't exist"""
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump({}, f)
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def clear_window(self):
        """Clear all widgets from current window"""
        # Destroy all widgets except background canvas
        for widget in self.root.winfo_children():
            if widget != self.bg_canvas:
                widget.destroy()
    
    def show_welcome_screen(self):
        """Display welcome screen with login/signup options"""
        self.clear_window()
        self.current_user = None
        
        # Remove background for welcome screen
        if self.bg_canvas:
            self.bg_canvas.destroy()
            self.bg_canvas = None
        
        # Set welcome screen background to light blue
        self.root.configure(bg='#e3f2fd')
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="40")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Digital Diary", 
                               font=("Segoe UI", 24, "bold"), foreground="#2c3e50")
        title_label.grid(row=0, column=0, pady=(0, 10))
        
        subtitle_label = ttk.Label(main_frame, text="Multi-User Secure Notes", 
                                  font=("Segoe UI", 12), foreground="#7f8c8d")
        subtitle_label.grid(row=1, column=0, pady=(0, 40))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, pady=20)
        
        # Login button
        login_btn = ttk.Button(button_frame, text="Login", 
                              command=self.show_login_screen, width=20)
        login_btn.grid(row=0, column=0, pady=10, padx=10)
        
        # Create account button
        signup_btn = ttk.Button(button_frame, text="Create New Account", 
                               command=self.show_signup_screen, width=20)
        signup_btn.grid(row=1, column=0, pady=10, padx=10)
        
        # Exit button
        exit_btn = ttk.Button(button_frame, text="Exit", 
                             command=self.root.quit, width=20)
        exit_btn.grid(row=2, column=0, pady=10, padx=10)
    
    def show_login_screen(self):
        """Display login screen"""
        self.clear_window()
        self.root.configure(bg='white')
        
        main_frame = ttk.Frame(self.root, padding="40")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Login", 
                               font=("Segoe UI", 18, "bold"))
        title_label.grid(row=0, column=0, pady=(0, 30))
        
        # Username
        ttk.Label(main_frame, text="Username:", font=("Segoe UI", 10)).grid(
            row=1, column=0, sticky=tk.W, pady=(0, 5))
        username_entry = ttk.Entry(main_frame, width=30, font=("Segoe UI", 10))
        username_entry.grid(row=2, column=0, pady=(0, 15))
        username_entry.focus()
        
        # Password
        ttk.Label(main_frame, text="Password:", font=("Segoe UI", 10)).grid(
            row=3, column=0, sticky=tk.W, pady=(0, 5))
        password_entry = ttk.Entry(main_frame, width=30, show="•", font=("Segoe UI", 10))
        password_entry.grid(row=4, column=0, pady=(0, 30))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, pady=10)
        
        # Login button
        login_btn = ttk.Button(button_frame, text="Login", width=15,
                              command=lambda: self.login_user(
                                  username_entry.get(), password_entry.get()))
        login_btn.grid(row=0, column=0, padx=5)
        
        # Back button
        back_btn = ttk.Button(button_frame, text="Back", width=15,
                             command=self.show_welcome_screen)
        back_btn.grid(row=0, column=1, padx=5)
        
        # Bind Enter key to login
        self.root.bind('<Return>', 
                      lambda e: self.login_user(username_entry.get(), password_entry.get()))
    
    def show_signup_screen(self):
        """Display signup screen"""
        self.clear_window()
        self.root.configure(bg='white')
        
        main_frame = ttk.Frame(self.root, padding="40")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Create New Account", 
                               font=("Segoe UI", 18, "bold"))
        title_label.grid(row=0, column=0, pady=(0, 30))
        
        # Username
        ttk.Label(main_frame, text="Username:", font=("Segoe UI", 10)).grid(
            row=1, column=0, sticky=tk.W, pady=(0, 5))
        username_entry = ttk.Entry(main_frame, width=30, font=("Segoe UI", 10))
        username_entry.grid(row=2, column=0, pady=(0, 15))
        username_entry.focus()
        
        # Password
        ttk.Label(main_frame, text="Password:", font=("Segoe UI", 10)).grid(
            row=3, column=0, sticky=tk.W, pady=(0, 5))
        password_entry = ttk.Entry(main_frame, width=30, show="•", font=("Segoe UI", 10))
        password_entry.grid(row=4, column=0, pady=(0, 15))
        
        # Confirm Password
        ttk.Label(main_frame, text="Confirm Password:", font=("Segoe UI", 10)).grid(
            row=5, column=0, sticky=tk.W, pady=(0, 5))
        confirm_password_entry = ttk.Entry(main_frame, width=30, show="•", font=("Segoe UI", 10))
        confirm_password_entry.grid(row=6, column=0, pady=(0, 30))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=7, column=0, pady=10)
        
        # Register button
        register_btn = ttk.Button(button_frame, text="Register", width=15,
                                command=lambda: self.register_user(
                                    username_entry.get(), 
                                    password_entry.get(), 
                                    confirm_password_entry.get()))
        register_btn.grid(row=0, column=0, padx=5)
        
        # Back button
        back_btn = ttk.Button(button_frame, text="Back", width=15,
                             command=self.show_welcome_screen)
        back_btn.grid(row=0, column=1, padx=5)
        
        # Bind Enter key to register
        self.root.bind('<Return>', 
                      lambda e: self.register_user(
                          username_entry.get(), 
                          password_entry.get(), 
                          confirm_password_entry.get()))
    
    def register_user(self, username, password, confirm_password):
        """Register a new user"""
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if len(username) < 3:
            messagebox.showerror("Error", "Username must be at least 3 characters long")
            return
        
        if len(password) < 4:
            messagebox.showerror("Error", "Password must be at least 4 characters long")
            return
        
        # Load existing users
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
        except:
            users = {}
        
        # Check if username already exists
        if username in users:
            messagebox.showerror("Error", "Username already exists")
            return
        
        # Hash password and save user
        hashed_password = self.hash_password(password)
        users[username] = hashed_password
        
        with open(self.users_file, 'w') as f:
            json.dump(users, f)
        
        # Create empty diary file for user
        diary_file = f"diary_{username}.txt"
        if not os.path.exists(diary_file):
            with open(diary_file, 'w') as f:
                f.write("")
        
        messagebox.showinfo("Success", "Account created successfully! Please login.")
        self.show_login_screen()
    
    def login_user(self, username, password):
        """Login existing user"""
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        # Load users
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
        except:
            users = {}
        
        # Check credentials
        hashed_password = self.hash_password(password)
        if username in users and users[username] == hashed_password:
            self.current_user = username
            self.show_diary_screen()
        else:
            messagebox.showerror("Error", "Invalid username or password")
    
    def show_diary_screen(self):
        """Display main diary screen with light pink background"""
        self.clear_window()
        self.root.unbind('<Return>')  # Remove Enter key binding
        
        # Create beautiful light pink background for diary
        self.create_diary_background()
        
        # Configure grid weights for responsive layout
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Header with light pink background
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        
        welcome_label = ttk.Label(header_frame, 
                                 text=f"Welcome, {self.current_user}!",
                                 font=("Segoe UI", 16, "bold"),
                                 background='lightpink')
        welcome_label.grid(row=0, column=0, sticky=tk.W)
        
        # Real-time clock
        self.clock_label = ttk.Label(header_frame, font=("Segoe UI", 10), 
                                    foreground="#7f8c8d", background='lightpink')
        self.clock_label.grid(row=0, column=1, sticky=tk.E)
        self.update_clock()
        
        # Text area with scrollbar
        text_frame = ttk.Frame(main_frame)
        text_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 20))
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)
        
        self.diary_text = scrolledtext.ScrolledText(
            text_frame, wrap=tk.WORD, width=60, height=15, 
            font=("Segoe UI", 11), padx=10, pady=10,
            bg='white', relief='solid', borderwidth=1)
        self.diary_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, pady=10)
        
        # Save Entry button
        save_btn = ttk.Button(button_frame, text="Save Entry", 
                             command=self.save_entry, width=15)
        save_btn.grid(row=0, column=0, padx=5)
        
        # View Entries button
        view_btn = ttk.Button(button_frame, text="View Entries", 
                             command=self.view_entries, width=15)
        view_btn.grid(row=0, column=1, padx=5)
        
        # Change Password button
        change_pwd_btn = ttk.Button(button_frame, text="Change Password", 
                                   command=self.show_change_password_screen, width=15)
        change_pwd_btn.grid(row=0, column=2, padx=5)
        
        # Logout button
        logout_btn = ttk.Button(button_frame, text="Logout", 
                               command=self.show_welcome_screen, width=15)
        logout_btn.grid(row=0, column=3, padx=5)
        
        # Exit button
        exit_btn = ttk.Button(button_frame, text="Exit", 
                             command=self.root.quit, width=15)
        exit_btn.grid(row=0, column=4, padx=5)
    
    def update_clock(self):
        """Update the real-time clock"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.clock_label.config(text=current_time)
        self.root.after(1000, self.update_clock)
    
    def save_entry(self):
        """Save the current diary entry"""
        entry_text = self.diary_text.get("1.0", tk.END).strip()
        
        if not entry_text:
            messagebox.showwarning("Warning", "Cannot save empty entry")
            return
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format entry with timestamp
        formatted_entry = f"\n--- Entry on {timestamp} ---\n{entry_text}\n"
        
        # Save to user's diary file
        diary_file = f"diary_{self.current_user}.txt"
        try:
            with open(diary_file, 'a', encoding='utf-8') as f:
                f.write(formatted_entry)
            
            # Clear text area after saving
            self.diary_text.delete("1.0", tk.END)
            messagebox.showinfo("Success", "Entry saved successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save entry: {str(e)}")
    
    def view_entries(self):
        """Display all diary entries in a new window"""
        diary_file = f"diary_{self.current_user}.txt"
        
        if not os.path.exists(diary_file):
            messagebox.showinfo("No Entries", "You haven't written any entries yet.")
            return
        
        try:
            with open(diary_file, 'r', encoding='utf-8') as f:
                entries = f.read()
            
            if not entries.strip():
                messagebox.showinfo("No Entries", "You haven't written any entries yet.")
                return
            
            # Create new window for viewing entries
            entries_window = tk.Toplevel(self.root)
            entries_window.title("My Diary Entries")
            entries_window.geometry("700x500")
            entries_window.resizable(True, True)
            self.center_window(entries_window)
            
            # Set light pink background for entries window
            entries_window.configure(bg='lightpink')
            
            # Main frame
            main_frame = ttk.Frame(entries_window, padding="10")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            entries_window.grid_rowconfigure(0, weight=1)
            entries_window.grid_columnconfigure(0, weight=1)
            main_frame.grid_rowconfigure(0, weight=1)
            main_frame.grid_columnconfigure(0, weight=1)
            
            # Text area with scrollbar
            text_area = scrolledtext.ScrolledText(
                main_frame, wrap=tk.WORD, width=80, height=25,
                font=("Segoe UI", 10), padx=10, pady=10,
                bg='white', relief='solid', borderwidth=1)
            text_area.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # Insert entries
            text_area.insert("1.0", entries)
            text_area.config(state=tk.DISABLED)  # Make it read-only
            
            # Close button
            close_btn = ttk.Button(main_frame, text="Close", 
                                  command=entries_window.destroy)
            close_btn.grid(row=1, column=0, pady=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read entries: {str(e)}")
    
    def show_change_password_screen(self):
        """Display change password screen"""
        change_pwd_window = tk.Toplevel(self.root)
        change_pwd_window.title("Change Password")
        change_pwd_window.geometry("400x300")
        change_pwd_window.resizable(False, False)
        self.center_window(change_pwd_window)
        change_pwd_window.transient(self.root)
        change_pwd_window.grab_set()
        
        # Set light pink background
        change_pwd_window.configure(bg='lightpink')
        
        main_frame = ttk.Frame(change_pwd_window, padding="30")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Change Password", 
                               font=("Segoe UI", 16, "bold"))
        title_label.grid(row=0, column=0, pady=(0, 30))
        
        # Current Password
        ttk.Label(main_frame, text="Current Password:", font=("Segoe UI", 10)).grid(
            row=1, column=0, sticky=tk.W, pady=(0, 5))
        current_password_entry = ttk.Entry(main_frame, width=25, show="•", font=("Segoe UI", 10))
        current_password_entry.grid(row=2, column=0, pady=(0, 15))
        current_password_entry.focus()
        
        # New Password
        ttk.Label(main_frame, text="New Password:", font=("Segoe UI", 10)).grid(
            row=3, column=0, sticky=tk.W, pady=(0, 5))
        new_password_entry = ttk.Entry(main_frame, width=25, show="•", font=("Segoe UI", 10))
        new_password_entry.grid(row=4, column=0, pady=(0, 15))
        
        # Confirm New Password
        ttk.Label(main_frame, text="Confirm New Password:", font=("Segoe UI", 10)).grid(
            row=5, column=0, sticky=tk.W, pady=(0, 5))
        confirm_password_entry = ttk.Entry(main_frame, width=25, show="•", font=("Segoe UI", 10))
        confirm_password_entry.grid(row=6, column=0, pady=(0, 30))
        
        def change_password():
            current_password = current_password_entry.get()
            new_password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()
            
            if not current_password or not new_password or not confirm_password:
                messagebox.showerror("Error", "Please fill in all fields")
                return
            
            if new_password != confirm_password:
                messagebox.showerror("Error", "New passwords do not match")
                return
            
            if len(new_password) < 4:
                messagebox.showerror("Error", "New password must be at least 4 characters long")
                return
            
            # Verify current password
            try:
                with open(self.users_file, 'r') as f:
                    users = json.load(f)
                
                hashed_current = self.hash_password(current_password)
                if users.get(self.current_user) != hashed_current:
                    messagebox.showerror("Error", "Current password is incorrect")
                    return
                
                # Update password
                users[self.current_user] = self.hash_password(new_password)
                
                with open(self.users_file, 'w') as f:
                    json.dump(users, f)
                
                messagebox.showinfo("Success", "Password changed successfully!")
                change_pwd_window.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to change password: {str(e)}")
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=7, column=0, pady=10)
        
        # Change button
        change_btn = ttk.Button(button_frame, text="Change Password", 
                               command=change_password, width=15)
        change_btn.grid(row=0, column=0, padx=5)
        
        # Cancel button
        cancel_btn = ttk.Button(button_frame, text="Cancel", 
                               command=change_pwd_window.destroy, width=15)
        cancel_btn.grid(row=0, column=1, padx=5)
        
        # Bind Enter key to change password
        change_pwd_window.bind('<Return>', lambda e: change_password())
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = DigitalDiaryApp()
    app.run()


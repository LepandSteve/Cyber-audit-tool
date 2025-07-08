import tkinter as tk
import socket
import sys
import os
import tkinter.messagebox as messagebox
from PIL import Image, ImageTk

from modules.gui_audit_view import AuditView
from modules.AD_audit.gui_ad_audit_view import ADAuditView
from modules.standard_audit import auto_updater 

# Define application version
APP_VERSION = "v2.1.0"

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Cybersecurity Audit Tool - DGDI / DSSI ({APP_VERSION})")
        self.geometry("1200x800")
        self.resizable(True, True)
        self.hostname = socket.gethostname()

        self.sidebar_visible = True
        self.is_fullscreen = False
        self.dark_mode_enabled = False

        self.sidebar_buttons = {}
        self.current_view = None

        self.setup_ui()
        self.show_home_view()

    def setup_ui(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.sidebar = tk.Frame(self, width=200, bg="#2c3e50")
        self.sidebar.grid(row=0, column=0, sticky="ns")

        self.main_area = tk.Frame(self, bg="#ecf0f1")
        self.main_area.grid(row=0, column=1, sticky="nsew")

        self.menu_toggle_btn = tk.Button(
            self,
            text="☰ Show Menu",
            bg="#16a085",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            command=self.toggle_sidebar
        )
        self.menu_toggle_btn.place(x=10, y=10)
        self.menu_toggle_btn.lower()

        self.toggle_btn = tk.Button(
            self.sidebar,
            text="⮘ Hide Menu",
            bg="#16a085",
            fg="white",
            relief=tk.FLAT,
            font=("Segoe UI", 10, "bold"),
            command=self.toggle_sidebar
        )
        self.toggle_btn.pack(fill=tk.X, pady=(0, 10))

        self.fullscreen_btn = tk.Button(
            self.sidebar,
            text="⛶ Full Screen",
            bg="#2980b9",
            fg="white",
            relief=tk.FLAT,
            font=("Segoe UI", 10, "bold"),
            command=self.toggle_fullscreen
        )
        self.fullscreen_btn.pack(fill=tk.X, pady=(0, 10))

        views = {
            "🏠 Home": self.show_home_view,
            "Standard Audit": self.show_audit_view,
            "AD Audit": self.show_ad_audit_view,
            "Settings": self.show_settings_view,
        }

        for name, command in views.items():
            btn = tk.Button(
                self.sidebar,
                text=name,
                bg="#34495e",
                fg="white",
                font=("Segoe UI", 11),
                relief=tk.FLAT,
                command=command
            )
            btn.pack(fill=tk.X, pady=2)
            self.sidebar_buttons[name] = btn

    def toggle_sidebar(self):
        if self.sidebar_visible:
            self.sidebar.grid_remove()
            self.menu_toggle_btn.lift()
            self.sidebar_visible = False
        else:
            self.sidebar.grid()
            self.menu_toggle_btn.lower()
            self.sidebar_visible = True

    def toggle_fullscreen(self):
        self.is_fullscreen = not self.is_fullscreen
        self.attributes("-fullscreen", self.is_fullscreen)
        if not self.is_fullscreen:
            self.geometry("1200x800")

    def toggle_theme(self):
        self.dark_mode_enabled = not self.dark_mode_enabled
        main_bg = "#1e272e" if self.dark_mode_enabled else "#ecf0f1"
        sidebar_bg = "#1e272e" if self.dark_mode_enabled else "#2c3e50"
        button_bg = "#34495e"

        self.main_area.config(bg=main_bg)
        self.sidebar.config(bg=sidebar_bg)

        for btn in self.sidebar_buttons.values():
            btn.config(bg=button_bg, fg="white")

        self.toggle_btn.config(bg="#16a085", fg="white")
        self.fullscreen_btn.config(bg="#2980b9", fg="white")

        if self.current_view:
            self.current_view.destroy()
            if isinstance(self.current_view, AuditView):
                self.show_audit_view()
            elif isinstance(self.current_view, ADAuditView):
                self.show_ad_audit_view()
            else:
                self.show_home_view()

    def check_for_updates(self):
        messagebox.showinfo("Check for Updates", f"✅ You are using the latest version ({APP_VERSION}).")

    def download_update(self):
        self.clear_main_area()

        # Progress label
        progress_label = tk.Label(
            self.main_area, text="📥 Downloading update...", font=("Segoe UI", 12),
            bg=self.main_area["bg"]
        )
        progress_label.pack(pady=30)

        # Progress bar
        progress_bar = tk.ttk.Progressbar(
            self.main_area, mode='indeterminate', length=300
        )
        progress_bar.pack(pady=10)
        progress_bar.start(10)

        self.update_idletasks()

        def perform_update():
            success = auto_updater.download_and_execute_latest_release()
            progress_bar.stop()
            if success:
                messagebox.showinfo("Update Ready", "✅ Update downloaded! The installer will now run.")
                self.quit()
            else:
                messagebox.showwarning("Update Failed", "⚠️ Could not download update. Please try again later.")

        # Run the updater after slight delay to allow UI rendering
        self.after(100, perform_update)

    def clear_main_area(self):
        for widget in self.main_area.winfo_children():
            widget.destroy()

    def show_home_view(self):
        self.clear_main_area()
        bg_color = "#ecf0f1" if not self.dark_mode_enabled else "#1e272e"
        home_frame = tk.Frame(self.main_area, bg=bg_color)
        home_frame.pack(fill=tk.BOTH, expand=True)
        self.current_view = home_frame

        # Background logo
        try:
            bg_path = resource_path("DGDI_logo2.jpg")
            bg_image = Image.open(bg_path).resize((1200, 800))
            self.bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(home_frame, image=self.bg_photo)
            bg_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        except Exception as e:
            print(f"[Background Error] {e}")

        fg_color = "#2c3e50" if not self.dark_mode_enabled else "white"

        welcome = tk.Label(
            home_frame,
            text="👋 Welcome!",
            font=("Segoe UI", 24, "bold"),
            bg=bg_color,
            fg=fg_color
        )
        welcome.place(relx=0.5, rely=0.2, anchor="center")

        prompt = tk.Label(
            home_frame,
            text="What type of audit would you like to conduct?",
            font=("Segoe UI", 15),
            bg=bg_color,
            fg=fg_color
        )
        prompt.place(relx=0.5, rely=0.26, anchor="center")

        # Buttons
        btn_style = {
            "font": ("Segoe UI", 12, "bold"),
            "width": 20,
            "height": 2,
            "bg": "#3498db",
            "fg": "white",
            "relief": tk.FLAT,
            "bd": 0,
            "activebackground": "#2980b9",
            "activeforeground": "white",
            "cursor": "hand2"
        }

        std_btn = tk.Button(home_frame, text="🔍 Standard Audit", command=self.show_audit_view, **btn_style)
        std_btn.place(relx=0.5, rely=0.34, anchor="center")

        ad_btn = tk.Button(home_frame, text="🛡️ AD Audit", command=self.show_ad_audit_view, **btn_style)
        ad_btn.place(relx=0.5, rely=0.43, anchor="center")

        # Version display
        version_label = tk.Label(
            home_frame,
            text=f"Version: {APP_VERSION}",
            font=("Segoe UI", 9),
            bg=bg_color,
            fg=fg_color
        )
        version_label.place(relx=0.99, rely=0.98, anchor="se")

    def show_audit_view(self):
        self.clear_main_area()
        view = AuditView(self.main_area, self.hostname, dark_mode=self.dark_mode_enabled)
        view.pack(fill=tk.BOTH, expand=True)
        self.current_view = view

    def show_ad_audit_view(self):
        self.clear_main_area()
        view = ADAuditView(self.main_area, self.hostname, dark_mode=self.dark_mode_enabled)
        view.pack(fill=tk.BOTH, expand=True)
        self.current_view = view

    def show_settings_view(self):
        self.clear_main_area()
        settings_frame = tk.Frame(self.main_area, bg="#ecf0f1" if not self.dark_mode_enabled else "#1e272e")
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        self.current_view = settings_frame

        title = tk.Label(
            settings_frame,
            text="⚙️ Application Settings",
            font=("Segoe UI", 16, "bold"),
            bg=settings_frame["bg"],
            fg="white" if self.dark_mode_enabled else "#2c3e50"
        )
        title.pack(pady=20)

        tk.Button(
            settings_frame,
            text="🔄 Check for Updates",
            bg="#3498db",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            relief=tk.FLAT,
            command=self.check_for_updates
        ).pack(fill=tk.X, pady=10)

        tk.Button(
            settings_frame,
            text="📥 Download & Install Update",
            bg="#f39c12",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            relief=tk.FLAT,
            command=self.download_update
        ).pack(fill=tk.X, pady=10)

        self.auto_update_enabled = tk.BooleanVar(value=False)
        tk.Checkbutton(
            settings_frame,
            text="Enable Auto-Update (not implemented)",
            variable=self.auto_update_enabled,
            bg=settings_frame["bg"],
            fg="white" if self.dark_mode_enabled else "#2c3e50",
            font=("Segoe UI", 11),
            selectcolor=settings_frame["bg"]
        ).pack(anchor="w", pady=5)

        tk.Button(
            settings_frame,
            text="🌓 Toggle Dark Theme",
            bg="#34495e",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            relief=tk.FLAT,
            command=self.toggle_theme
        ).pack(fill=tk.X, pady=10)

        tk.Button(
            settings_frame,
            text="❌ Quit Application",
            bg="#e74c3c",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            relief=tk.FLAT,
            command=self.quit
        ).pack(fill=tk.X, pady=30)

if __name__ == "__main__":
    app = MainApp()
    app.mainloop()

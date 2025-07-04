import tkinter as tk
import socket
import sys
import os

from modules.gui_audit_view import AuditView
from modules.AD_audit.gui_ad_audit_view import ADAuditView 

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cybersecurity Audit Tool - DGDI / DSSI")
        self.geometry("1200x800")
        self.resizable(True, True)
        self.hostname = socket.gethostname()

        self.sidebar_visible = True
        self.is_fullscreen = False

        self.sidebar_buttons = {}
        self.current_view = None

        self.setup_ui()
        self.show_audit_view()

    def setup_ui(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Sidebar
        self.sidebar = tk.Frame(self, width=200, bg="#2c3e50")
        self.sidebar.grid(row=0, column=0, sticky="ns")

        # Main area
        self.main_area = tk.Frame(self, bg="#ecf0f1")
        self.main_area.grid(row=0, column=1, sticky="nsew")

        # Toggle sidebar button (in main root window)
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
        self.menu_toggle_btn.lower()  # Hidden by default

        # Inside sidebar: Hide button
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

        # Fullscreen button
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

        # View buttons
        views = {
            "Standard Audit": self.show_audit_view,
             "AD Audit": self.show_ad_audit_view,  
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

    def clear_main_area(self):
        for widget in self.main_area.winfo_children():
            widget.destroy()

    def show_audit_view(self):
        self.clear_main_area()
        audit_view = AuditView(self.main_area, self.hostname)
        audit_view.pack(fill=tk.BOTH, expand=True)

    def show_ad_audit_view(self):
        self.clear_main_area()
        ad_view = ADAuditView(self.main_area)
        ad_view.pack(fill="both", expand=True)


if __name__ == "__main__":
    app = MainApp()
    app.mainloop()

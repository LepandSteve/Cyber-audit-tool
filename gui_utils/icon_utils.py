
import os
from tkinter import PhotoImage

def set_window_icon(root):
    try:
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if os.path.exists(icon_path):
            img = PhotoImage(file=icon_path)
            root.iconphoto(True, img)
    except:
        pass


themes = {
    "light": {
        "TK_THEME": "clam",
        "TCL_THEME": "azure.tcl",
        "TEXT_BG": "#ffffff",
        "TEXT_FG": "#000000",
        "ACCENT_COLOR": "green",
        "ERROR_COLOR": "red"
    },
    "dark": {
        "TK_THEME": "alt",
        "TCL_THEME": "azure-dark.tcl",
        "TEXT_BG": "#1e1e1e",
        "TEXT_FG": "#ffffff",
        "ACCENT_COLOR": "lime",
        "ERROR_COLOR": "orange red"
    }
}

current_theme = "dark"

def toggle_theme(root, style):
    global current_theme
    current_theme = "light" if current_theme == "dark" else "dark"
    root.tk.call("source", themes[current_theme]["TCL_THEME"])
    style.theme_use(themes[current_theme]["TK_THEME"])

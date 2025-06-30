
from tkinter import filedialog
import json
from fpdf import FPDF
from datetime import datetime

def export_report(content, root):
    filetypes = [
        ("Text File", "*.txt"),
        ("JSON File", "*.json"),
        ("HTML File", "*.html"),
        ("PDF File", "*.pdf")
    ]
    default_filename = f"cyber_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=filetypes, initialfile=default_filename)

    if not path:
        return

    if path.endswith(".json"):
        with open(path, "w") as f:
            f.write(json.dumps({"report": content}, indent=4))
    elif path.endswith(".html"):
        with open(path, "w") as f:
            html_content = f"<html><body><pre>{content}</pre></body></html>"
            f.write(html_content)
    elif path.endswith(".pdf"):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font("Courier", size=10)
        for line in content.splitlines():
            pdf.cell(0, 10, line, ln=True)
        pdf.output(path)
    else:
        with open(path, "w") as f:
            f.write(content)

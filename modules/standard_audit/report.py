# modules/report.py

import os
import textwrap
import json
from datetime import datetime
from fpdf import FPDF
from modules.standard_audit.report_utils import translate, sanitize_for_pdf, calculate_final_score, translate_details

class PDFReport(FPDF):
    def __init__(self, lang="en"):
        super().__init__()
        self.lang = lang
        self.set_auto_page_break(auto=True, margin=15)
        self.logo_path = "dgdi_logo.png"
        self.set_font("Arial", "", 10)

    def header(self):
        if os.path.exists(self.logo_path):
            self.image(self.logo_path, 10, 8, 25)
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, "DGDI - DSSI", border=False, ln=True, align="C")
        self.set_font("Arial", "", 10)
        self.cell(0, 10, translate("Cybersecurity Audit Report", self.lang), border=False, ln=True, align="C")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

def generate_pdf_report(results, target, hostname, lang, filename, final_score=0.0):
    pdf = PDFReport(lang)
    pdf.add_page()

    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 10, f"{translate('Target', lang)}: {target}", ln=True)
    pdf.cell(0, 10, f"{translate('Hostname', lang)}: {hostname}", ln=True)
    pdf.cell(0, 10, f"{translate('Date', lang)}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(5)

    col_widths = [40, 25, 20, 105]
    line_height = 5

    headers = ["Module", "Status", "Score", "Details"]
    pdf.set_font("Arial", "B", 10)
    for i, header in enumerate(headers):
        pdf.cell(col_widths[i], 8, translate(header, lang), border=1, align="C")
    pdf.ln()

    pdf.set_font("Arial", "", 9)

    for entry in results:
        module = sanitize_for_pdf(str(entry.get("module", "")))
        status = sanitize_for_pdf(translate(str(entry.get("status", "")), lang))
        score = f"{float(entry.get('score', 0)):.2f}"

        raw_details = str(entry.get("details", ""))
        translated_details = translate_details(raw_details, lang)

        max_detail_chars = 500
        if len(translated_details) > max_detail_chars:
            details = translated_details[:max_detail_chars] + " ... (truncated)"
        else:
            details = translated_details

        def wrap_text(text, width, pdf):
            avg_char_width = pdf.get_string_width("M") or 1
            max_chars = int(width / avg_char_width)
            return textwrap.fill(text, width=max_chars, break_long_words=True)

        module_wrapped = wrap_text(module, col_widths[0], pdf)
        status_wrapped = wrap_text(status, col_widths[1], pdf)
        score_wrapped = wrap_text(score, col_widths[2], pdf)
        details_wrapped = "\n".join([wrap_text(line, col_widths[3], pdf) for line in details.splitlines()])

        max_lines = max(
            module_wrapped.count('\n') + 1,
            status_wrapped.count('\n') + 1,
            score_wrapped.count('\n') + 1,
            details_wrapped.count('\n') + 1,
        )
        row_height = line_height * max_lines

        if pdf.get_y() + row_height > pdf.h - pdf.b_margin:
            pdf.add_page()

        x_start = pdf.get_x()
        y_start = pdf.get_y()

        pdf.multi_cell(col_widths[0], line_height, sanitize_for_pdf(module_wrapped), border=1)
        pdf.set_xy(x_start + col_widths[0], y_start)

        pdf.multi_cell(col_widths[1], line_height, sanitize_for_pdf(status_wrapped), border=1)
        pdf.set_xy(x_start + col_widths[0] + col_widths[1], y_start)

        pdf.multi_cell(col_widths[2], line_height, sanitize_for_pdf(score_wrapped), border=1, align="C")
        pdf.set_xy(x_start + col_widths[0] + col_widths[1] + col_widths[2], y_start)

        pdf.multi_cell(col_widths[3], line_height, sanitize_for_pdf(details_wrapped), border=1)

    pdf.ln(5)
    summary = calculate_final_score(results)
    pdf.set_font("Arial", "B", 11)
    final_score_str = f"{translate('Final Score', lang)}: {summary['final_score']} - {translate(summary['overall_status'], lang)}"
    pdf.cell(0, 10, final_score_str, ln=True)

    try:
        pdf.output(filename)
    except Exception as e:
        print(f"Error writing PDF report: {e}")

def generate_txt_report(results, target, hostname, lang, filename, final_score=0.0):
    lines = [
        f"{translate('Cybersecurity Audit Report', lang)}",
        f"{translate('Target', lang)}: {target}",
        f"{translate('Hostname', lang)}: {hostname}",
        f"{translate('Date', lang)}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ""
    ]

    for entry in results:
        lines.append(f"{translate('Module', lang)}: {entry.get('module', '')}")
        lines.append(f"{translate('Status', lang)}: {translate(entry.get('status', ''), lang)}")
        lines.append(f"{translate('Score', lang)}: {float(entry.get('score', 0)):.2f}")
        details = translate_details(entry.get("details", ""), lang)
        lines.append(f"{translate('Details', lang)}: {details}")
        lines.append("-" * 50)

    summary = calculate_final_score(results)
    lines.append("")
    lines.append(f"{translate('Final Score', lang)}: {summary['final_score']} - {translate(summary['overall_status'], lang)}")

    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    except Exception as e:
        print(f"Error writing TXT report: {e}")

def generate_html_report(results, target, hostname, lang, filename, final_score=0.0):
    summary = calculate_final_score(results)

    html = f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
    <meta charset="UTF-8">
    <title>{translate('Cybersecurity Audit Report', lang)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ text-align: center; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .summary {{ margin-top: 20px; font-weight: bold; font-size: 1.1em; }}
    </style>
</head>
<body>
    <h1>DGDI - DSSI</h1>
    <h2>{translate('Cybersecurity Audit Report', lang)}</h2>
    <p><strong>{translate('Target', lang)}:</strong> {target}</p>
    <p><strong>{translate('Hostname', lang)}:</strong> {hostname}</p>
    <p><strong>{translate('Date', lang)}:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

    <table>
        <thead>
            <tr>
                <th>{translate('Module', lang)}</th>
                <th>{translate('Status', lang)}</th>
                <th>{translate('Score', lang)}</th>
                <th>{translate('Details', lang)}</th>
            </tr>
        </thead>
        <tbody>
"""

    for entry in results:
        html += "<tr>"
        html += f"<td>{entry.get('module', '')}</td>"
        html += f"<td>{translate(entry.get('status', ''), lang)}</td>"
        html += f"<td>{float(entry.get('score', 0)):.2f}</td>"
        details = translate_details(entry.get('details', ''), lang).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
        html += f"<td>{details}</td>"
        html += "</tr>"

    html += f"""
        </tbody>
    </table>

    <p class="summary">{translate('Final Score', lang)}: {summary['final_score']} - {translate(summary['overall_status'], lang)}</p>
</body>
</html>"""

    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception as e:
        print(f"Error writing HTML report: {e}")

def generate_json_report(results, target, hostname, lang, filename, final_score=0.0):
    summary = calculate_final_score(results)

    report = {
        "organization": "DGDI - DSSI",
        "title": translate("Cybersecurity Audit Report", lang),
        "target": target,
        "hostname": hostname,
        "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "results": results,
        "final_score": summary['final_score'],
        "overall_status": translate(summary['overall_status'], lang)
    }

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Error writing JSON report: {e}")

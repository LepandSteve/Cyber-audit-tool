import os
from fpdf import FPDF

# Translation dictionary and function
def translate(text, lang):
    translations = {
        "Cybersecurity Audit Report": {"fr": "Rapport d'Audit Cybersécurité"},
        "Target": {"fr": "Cible"},
        "Hostname": {"fr": "Nom d'hôte"},
        "Date": {"fr": "Date"},
        "Module": {"fr": "Module"},
        "Status": {"fr": "Statut"},
        "Score": {"fr": "Score"},
        "Details": {"fr": "Détails"},
        "Final Score": {"fr": "Score Final"},
        "Pass": {"fr": "Réussite"},
        "Warning": {"fr": "Avertissement"},
        "Error": {"fr": "Erreur"},
        "Info": {"fr": "Information"},
        "Skipped": {"fr": "Ignoré"},
    }
    return translations.get(text, {}).get(lang, text)

# ✅ NEW: Translate common audit phrases in 'details'
def translate_details(text, lang):
    if lang != "fr":
        return text

    replacements = {
        "No brute-force susceptible services": "Aucun service vulnérable à la force brute détecté",
        "No risky or outdated service banners": "Aucune bannière de service obsolète ou risquée détectée",
        "No obviously dangerous services are publicly exposed": "Aucun service dangereux n'est exposé publiquement",
        "No weak or deprecated protocols detected": "Aucun protocole faible ou obsolète détecté",
        "Banner grabbing skipped for private/internal IP": "Récupération de bannière ignorée pour une IP privée/interne",
        "Reverse DNS Lookup skipped": "Recherche DNS inverse ignorée",
        "IP is private/internal and does not require geolocation": "IP privée/interne, la géolocalisation n'est pas requise",
        "WHOIS lookup skipped": "Recherche WHOIS ignorée",
        "Remote Port Activity for": "Activité des ports distants pour",
        "Open Ports Detected on": "Ports ouverts détectés sur",
        "All tested ports appear filtered": "Tous les ports testés semblent filtrés",
        "Firewall likely active": "Pare-feu probablement actif",
        "No known default credentials": "Aucun identifiant par défaut connu détecté",
        "No static DB vulnerabilities found": "Aucune vulnérabilité connue détectée dans la base de données",
        "Remote system antivirus status cannot be directly verified": "Le statut de l'antivirus du système distant ne peut pas être vérifié directement",
        "CVE Lookup Results": "Résultats de la recherche CVE",
        "Skipped NTP check for internal/private IP": "Vérification NTP ignorée pour une IP privée/interne",
        "Host is up": "Hôte actif",
        "Port": "Port",
        "Banner": "Bannière",
        "Error grabbing banner": "Erreur lors de la récupération de la bannière",
        "No banner retrieved": "Aucune bannière récupérée",
        "No banner received": "Aucune bannière reçue",
        "No action needed": "Aucune action requise",
    }

    for en, fr in replacements.items():
        text = text.replace(en, fr)

    return text

# ✅ FIXED: Strip all non-ASCII characters (emojis, symbols) to avoid "??" in PDF
def sanitize_for_pdf(text):
    if not isinstance(text, str):
        text = str(text)
    return ''.join(c for c in text if ord(c) < 128)

# ✅ FIXED: Use custom thresholds (Pass ≥ 8, Warning ≥ 6, else Error)
def calculate_final_score(results):
    total_score = 0
    count = 0
    for res in results:
        try:
            total_score += float(res.get("score", 0))
            count += 1
        except (ValueError, TypeError):
            continue

    average = total_score / count if count > 0 else 0.0

    if average >= 8.0:
        status = "Pass"
    elif average >= 6.0:
        status = "Warning"
    else:
        status = "Error"

    return {"final_score": f"{average:.2f}", "overall_status": status}

# PDF Export Class
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

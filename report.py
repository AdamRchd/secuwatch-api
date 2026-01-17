from fpdf import FPDF

class PDFReport(FPDF):
    def header(self):
        self.set_fill_color(30, 41, 59)
        self.rect(0, 0, 210, 40, 'F')
        
        self.set_font('Arial', 'B', 20)
        self.set_text_color(255, 255, 255)
        self.cell(0, 30, 'SecuWatch // Rapport d\'Audit', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf(domain, score, ssl_data, headers_data, open_ports, security_txt):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, f"Cible : {domain}", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 14)
    if score > 70:
        pdf.set_text_color(34, 197, 94)
        verdict = "BON"
    elif score > 50:
        pdf.set_text_color(234, 179, 8)
        verdict = "MOYEN"
    else:
        pdf.set_text_color(239, 68, 68)
        verdict = "CRITIQUE"

    pdf.cell(0, 10, f"Score de Sécurité : {score}/100 ({verdict})", ln=True)
    pdf.ln(10)
    
    pdf.set_text_color(0, 0, 0)

    pdf.set_font("Arial", "B", 12)
    pdf.set_fill_color(200, 220, 255)
    pdf.cell(0, 10, "1. Analyse SSL / HTTPS", 0, 1, 'L', fill=True)
    pdf.set_font("Arial", "", 11)
    
    pdf.ln(2)
    pdf.cell(50, 10, f"Certificat Valide : {'OUI' if ssl_data['valid'] else 'NON'}", ln=True)
    if ssl_data['valid']:
        pdf.cell(50, 10, f"Expiration : dans {ssl_data['days_left']} jours", ln=True)
        issuer = ssl_data['issuer'].encode('latin-1', 'replace').decode('latin-1')
        pdf.cell(50, 10, f"Emetteur : {issuer}", ln=True)
    
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "2. Headers de Sécurité (OWASP)", 0, 1, 'L', fill=True)
    pdf.set_font("Arial", "", 10)
    pdf.ln(2)

    for header, status in headers_data.items():
        clean_status = status.encode('latin-1', 'replace').decode('latin-1')
        if "Présent" in status:
            pdf.set_text_color(0, 100, 0)
        else:
            pdf.set_text_color(150, 0, 0)
        
        pdf.cell(90, 8, header, border=1)
        pdf.cell(0, 8, clean_status, border=1, ln=True)

    pdf.ln(10)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "3. Reconnaissance Réseau & OSINT", 0, 1, 'L', fill=True)
    pdf.set_font("Arial", "", 11)
    pdf.ln(2)

    pdf.cell(60, 10, "Ports Ouverts (Top 10) : ", 0, 0)
    if open_ports:
        pdf.set_text_color(200, 0, 0)
        ports_str = ", ".join(map(str, open_ports))
        pdf.cell(0, 10, ports_str, 0, 1)
    else:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 10, "Aucun (Safe)", 0, 1)

    pdf.set_text_color(0, 0, 0)
    pdf.cell(60, 10, "Fichier security.txt : ", 0, 0)
    if security_txt:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 10, "Trouvé", 0, 1)
    else:
        pdf.set_text_color(200, 100, 0)
        pdf.cell(0, 10, "Non trouvé", 0, 1)

    return pdf.output(dest='S').encode('latin-1')
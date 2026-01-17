import socket
import ssl
import requests
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

def get_ssl_details(hostname):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(3.0)

    try:
        conn.connect((hostname, 443))
        ssl_info = conn.getpeercert()
        
        date_format = r'%b %d %H:%M:%S %Y %Z'
        expire_date = datetime.strptime(ssl_info['notAfter'], date_format)
        days_left = (expire_date - datetime.now()).days
        
        return {
            "valid": True,
            "days_left": days_left,
            "issuer": dict(x[0] for x in ssl_info['issuer'])['commonName']
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}
    finally:
        conn.close()

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        checklist = {
            "Strict-Transport-Security": "Manquant (Critique: Force le HTTPS)",
            "X-Frame-Options": "Manquant (Risque: Clickjacking)",
            "X-Content-Type-Options": "Manquant (Risque: MIME Sniffing)",
            "Content-Security-Policy": "Manquant (Risque: XSS & Injections)",
            "Permissions-Policy": "Manquant (Recommandé: Contrôle des features navigateur)"
        }
        
        results = {}
        score = 100
        
        for header, message in checklist.items():
            if header in headers:
                results[header] = "✅ Présent"
            else:
                results[header] = f"❌ {message}"
                score -= 20
        
        return max(0, score), results

    except requests.exceptions.RequestException as e:
        return 0, {"Erreur": f"Impossible de contacter le site: {str(e)}"}

def check_single_port(hostname, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((hostname, port))
    sock.close()
    return port if result == 0 else None

def scan_ports(hostname):
    target_ports = [21, 22, 25, 53, 80, 443, 3306, 5432, 8080, 8443]
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {executor.submit(check_single_port, hostname, port): port for port in target_ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future.result()
            if port:
                open_ports.append(port)
    
    return sorted(open_ports)

def check_security_txt(domain):
    urls = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt"
    ]
    
    for url in urls:
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200 and "Contact:" in response.text:
                return True
        except:
            continue
    return False
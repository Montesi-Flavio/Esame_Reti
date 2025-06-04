"""
Header analysis functionality for email investigation.
"""

import re
import sys
import os
from email.parser import HeaderParser
from connectors import check_ip_safety, check_blacklist

# Importa la funzione clean_text_for_html dal modulo output.html_output
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from output.html_output import clean_text_for_html
except ImportError:
    # Definisci una versione locale della funzione se l'importazione fallisce
    def clean_text_for_html(text):
        if not text or not isinstance(text, str):
            return text
        text = re.sub(r'\n\s*\n', '\n', text)
        text = text.replace('\n', ' ').strip()
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'Mostra Altri Header', '', text)
        return text.strip()

def parse_email_headers(mail_data, investigation=False):
    """
    Parse email headers and optionally investigate for security issues.
    
    Args:
        mail_data: Email data as string
        investigation: Whether to perform security investigation
        
    Returns:
        Dictionary of parsed header information
    """
    headers = HeaderParser().parsestr(mail_data, headersonly=True)
    parsed_headers = {"Data": {}, "Investigation": {}}

    # Extract basic header data
    for k, v in headers.items():
        parsed_headers["Data"][k.lower()] = v.replace('\t', '').replace('\n', '')

    # Handle special case for 'received' headers which can be multiple
    if 'received' in parsed_headers["Data"]:
        parsed_headers["Data"]['received'] = ' '.join(headers.get_all('Received', [])).replace('\t', '').replace('\n', '')
    
    # Crea una versione formattata per HTML degli header
    html_header_view = {}
    
    # Ordine prioritario per gli header più importanti
    priority_headers = ['subject', 'from', 'to', 'cc', 'bcc', 'date', 'message-id', 'reply-to']
    
    # Prima aggiungi gli header prioritari in ordine
    for header in priority_headers:
        if header in parsed_headers["Data"]:
            # Pulisci il valore dell'header rimuovendo caratteri indesiderati
            clean_value = clean_text_for_html(parsed_headers["Data"][header])
            
            # Formattazione speciale per ciascun tipo di header
            if header == 'from':
                html_header_view['Mittente'] = f'<strong>{clean_value}</strong>'
            elif header == 'to':
                html_header_view['Destinatario'] = clean_value
            elif header == 'cc':
                html_header_view['CC'] = clean_value
            elif header == 'bcc':
                html_header_view['BCC'] = clean_value
            elif header == 'subject':
                html_header_view['Oggetto'] = f'<h4>{clean_value}</h4>'
            elif header == 'date':
                html_header_view['Data'] = f'<em>{clean_value}</em>'
            elif header == 'message-id':
                html_header_view['ID Messaggio'] = f'<code>{clean_value}</code>'
            elif header == 'reply-to':
                html_header_view['Rispondi A'] = clean_value
    
    # Poi aggiungi gli altri header ordinati alfabeticamente
    other_headers = {}
    for k, v in sorted(parsed_headers["Data"].items()):
        if k not in priority_headers:
            other_headers[k] = clean_text_for_html(v)
    
    # Aggiungi la sezione "Altri Header" se ci sono altri header
    if other_headers:
        other_headers_html = """
        <div class="accordion" id="headerAccordion">
            <div class="card">
            
                <div id="collapseDetails" class="collapse" aria-labelledby="headingDetails" data-parent="#headerAccordion">
                    <div class="card-body">
                        <table class="table table-sm table-striped">
                            <tbody>
        """
        
        for k, v in other_headers.items():
            other_headers_html += f'<tr><th>{k}</th><td><small>{v}</small></td></tr>'
            
        other_headers_html += """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        """
        html_header_view['Dettagli Tecnici'] = other_headers_html

    # Aggiungi HTML_View ai dati di output
    parsed_headers["HTML_View"] = html_header_view

    # Perform security investigation if requested
    if investigation:
        # Extract sender IP from Received headers
        received_headers = headers.get_all('Received')
        sender_ip = extract_sender_ip(received_headers) if received_headers else None

        if sender_ip:
            # Check IP against VirusTotal
            ip_investigation = investigate_sender_ip(sender_ip)
            if ip_investigation:
                parsed_headers["Investigation"]["X-Sender-Ip"] = ip_investigation
                
                # Aggiungi una versione HTML formattata per l'IP del mittente
                safety_class = "success" if ip_investigation["Safety"] == "Safe" else "danger"
                html_ip_info = f"""
                <div class="card mb-3">
                    <div class="card-header bg-light">
                        <h5><i class="fa fa-shield-alt"></i> Analisi IP Mittente</h5>
                    </div>
                    <div class="card-body">
                        <p><strong>IP:</strong> <code>{sender_ip}</code></p>
                        <p><strong>Stato:</strong> <span class="badge badge-{safety_class}">{ip_investigation["Safety"]}</span></p>
                        <p><strong>Rilevamenti:</strong> {ip_investigation["Positives"]}</p>
                        <div class="btn-group">
                            <a href="{ip_investigation["Virustotal"]}" target="_blank" class="btn btn-sm btn-outline-secondary">
                                VirusTotal <i class="fa fa-external-link-alt"></i>
                            </a>
                            <a href="{ip_investigation["Abuseipdb"]}" target="_blank" class="btn btn-sm btn-outline-secondary">
                                AbuseIPDB <i class="fa fa-external-link-alt"></i>
                            </a>
                        </div>
                    </div>
                </div>
                """
                parsed_headers["HTML_Investigation"] = {"Sender_IP": html_ip_info}

            # Check IP against blacklists
            blacklist_results = check_ip_blacklists(sender_ip)
            if blacklist_results:
                parsed_headers["Investigation"]["Blacklist_Check"] = blacklist_results
                
                # Aggiungi una versione HTML formattata per i risultati della blacklist
                blacklist_class = "danger" if blacklist_results["Blacklist_Status"] == "Blacklisted" else "success"
                html_blacklist_info = f"""
                <div class="card">
                    <div class="card-header bg-light">
                        <h5><i class="fa fa-ban"></i> Controllo Blacklist</h5>
                    </div>
                    <div class="card-body">
                        <p><strong>Stato:</strong> <span class="badge badge-{blacklist_class}">{blacklist_results["Blacklist_Status"]}</span></p>
                """
                
                if "Blacklist" in blacklist_results:
                    html_blacklist_info += "<p><strong>Liste:</strong></p><ul>"
                    for bl in blacklist_results["Blacklist"]:
                        html_blacklist_info += f"<li>{bl}</li>"
                    html_blacklist_info += "</ul>"
                
                html_blacklist_info += """
                    </div>
                </div>
                """
                
                if "HTML_Investigation" not in parsed_headers:
                    parsed_headers["HTML_Investigation"] = {}
                parsed_headers["HTML_Investigation"]["Blacklist"] = html_blacklist_info

    return parsed_headers

def extract_sender_ip(received_headers):
    """
    Extract the sender IP from Received headers.
    
    Args:
        received_headers: List of Received headers
        
    Returns:
        Sender IP or None if not found
    """
    if not received_headers:
        return None
        
    # The last "Received" header typically contains the originating server info
    last_received = received_headers[-1]
    sender_ip_match = re.search(r'\[([0-9.]+)\]', last_received)
    return sender_ip_match.group(1) if sender_ip_match else None

def investigate_sender_ip(ip):
    """
    Investigate a sender IP for security issues.
    
    Args:
        ip: IP address to investigate
        
    Returns:
        Dictionary with investigation results
    """
    # Check IP on VirusTotal
    safe, positives, error = check_ip_safety(ip)
    if safe is None:
        if error:
            return {
                "Virustotal": f"https://www.virustotal.com/gui/search/{ip}",
                "Abuseipdb": f"https://www.abuseipdb.com/check/{ip}",
                "Safety": "Unknown",
                "Positives": "N/A",
                "Error": error
            }
        return None
        
    safety_status = "Safe" if safe else "Unsafe"
    return {
        "Virustotal": f"https://www.virustotal.com/gui/search/{ip}",
        "Abuseipdb": f"https://www.abuseipdb.com/check/{ip}",
        "Safety": safety_status,
        "Positives": positives
    }

def check_ip_blacklists(ip):
    """
    Check if an IP is on any blacklists.
    
    Args:
        ip: IP address to check
        
    Returns:
        Dictionary with blacklist check results
    """
    blacklisted, blacklist = check_blacklist(ip)
    if blacklisted:
        return {
            "Blacklist_Status": "Blacklisted",
            "Blacklist": blacklist
        }
    else:
        return {
            "Blacklist_Status": "Not Blacklisted"
        }
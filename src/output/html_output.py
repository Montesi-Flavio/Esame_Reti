"""
Funzionalità di generazione dell'output HTML.
Versione migliorata con funzioni separate per ogni sezione dell'output.
"""

import os
import re
import email.header
from html_generator import generate_table_from_json
from datetime import datetime
import json
from html import escape
from .styles import get_base_styles

###############################################################################
# UTILITY PER LA PULIZIA E LA FORMATTAZIONE DEL TESTO
###############################################################################

def clean_text_for_html(text):
    """
    Pulisce il testo per la visualizzazione HTML rimuovendo caratteri di controllo indesiderati.
    
    Args:
        text: Testo da pulire
    
    Returns:
        Testo pulito pronto per la visualizzazione HTML
    """
    if not text or not isinstance(text, str):
        return text

    # Rimuove sequenze di newline e whitespace multipli
    text = re.sub(r'\n\s*\n', '\n', text)

    # Rimuove newline e spazi multipli
    text = re.sub(r'\s*\n\s*', ' ', text)

    # Rimuove spazi multipli
    text = re.sub(r'\s+', ' ', text)

    # Rimuove stringhe di controllo comuni
    text = re.sub(r'Mostra Altri Header', '', text)

    # Rimuove newline residui
    text = text.replace('\n', '').strip()

    return text.strip()

def format_multiline_text_for_html(text):
    """
    Formatta il testo multiriga per la visualizzazione HTML, preservando le interruzioni di riga.
    
    Args:
        text: Testo multiriga da formattare
    
    Returns:
        Testo formattato per HTML con <br> al posto dei newline
    """
    if not text or not isinstance(text, str):
        return text
    
    # Sostituisce i caratteri di nuova riga con tag <br>
    text = text.replace('\n', '<br>')
    
    # Importante: NON rimuoviamo gli spazi perché potrebbe causare problemi con la formattazione
    # del testo. Rimuoviamo solo spazi multipli consecutivi.
    text = re.sub(r' {2,}', ' ', text)
    
    # Rimuove i <br> consecutivi mantenendone solo uno
    text = re.sub(r'<br>\s*<br>', '<br>', text)
    
    return text.strip()

def decode_header_value(value):
    """
    Decodifica valori di header che potrebbero contenere codifiche MIME encoded-word (RFC 2047).
    Es. =?utf-8?q?testo_codificato?= viene convertito in 'testo codificato'
    
    Args:
        value: Valore dell'header da decodificare
        
    Returns:
        Stringa decodificata
    """
    if not value or not isinstance(value, str):
        return value
    
    try:
        # Utilizza il modulo email.header per decodificare
        decoded_parts = []
        
        # Sostituisce spazi che potrebbero separare codifiche consecutive
        # Il pattern rileva sequenze come =?utf-8?q?parte1?= =?utf-8?q?parte2?=
        encoded_pattern = r'(=\?[^?]+\?[BQbq]\?[^?]+\?=)\s+(=\?[^?]+\?[BQbq]\?[^?]+\?=)'
        while re.search(encoded_pattern, value):
            value = re.sub(encoded_pattern, r'\1\2', value)
        
        # Decodifica utilizzando email.header
        parts = email.header.decode_header(value)
        for part, encoding in parts:
            if isinstance(part, bytes):
                if encoding:
                    try:
                        decoded_parts.append(part.decode(encoding))
                    except (UnicodeDecodeError, LookupError):
                        # Fallback all'utf-8 se l'encoding specificato fallisce
                        try:
                            decoded_parts.append(part.decode('utf-8', errors='replace'))
                        except:
                            decoded_parts.append(part.decode('latin-1', errors='replace'))
                else:
                    # Se l'encoding non è specificato, prova prima utf-8
                    try:
                        decoded_parts.append(part.decode('utf-8', errors='replace'))
                    except:
                        decoded_parts.append(part.decode('latin-1', errors='replace'))
            else:
                # Se è già una stringa
                decoded_parts.append(str(part))
                
        result = ''.join(decoded_parts)
        return result
    except Exception as e:
        # In caso di errore, ritorna il valore originale
        return value

def format_email_field(key, value):
    """
    Formatta un campo email per una migliore visualizzazione HTML.
    
    Args:
        key: Nome del campo
        value: Valore del campo
    
    Returns:
        Valore formattato
    """
    raw_value = str(value)
    decoded_value = decode_header_value(raw_value)
    
    # Per campi con possibile testo multiriga, utilizziamo la nuova funzione
    if "\n" in decoded_value:
        formatted_value = format_multiline_text_for_html(decoded_value)
    else:
        # Altrimenti, puliamo il testo normalmente
        clean_value = clean_text_for_html(decoded_value).strip()
        formatted_value = clean_value
    
    # Speciali formattazioni per alcuni campi
    if "from" in key.lower() or "received" in key.lower() or "by" in key.lower():
        for separator in ["by ", "from ", "for ", "with ", "id ", "; "]:
            if separator in formatted_value:
                formatted_value = formatted_value.replace(separator, "<br>" + separator)
        if "received" in key.lower():
            formatted_value = formatted_value.replace("[", "<br>[").replace("(", "<br>(")
    
    return formatted_value

###############################################################################
# GENERAZIONE DELLE SINGOLE SEZIONI HTML
###############################################################################

def generate_information_section(result):
    """
    Genera la sezione delle informazioni generali dell'email.
    
    Args:
        result: Risultato dell'analisi per una singola email
    
    Returns:
        Codice HTML della sezione informazioni
    """
    if "Information" not in result:
        return ""
    
    info = result["Information"]
    
    return f"""
    <div class="section">
        <h2>Informazioni</h2>
        <table>
            <tr>
                <th>Nome File</th>
                <td>{info.get("Scan", {}).get("Filename", "Sconosciuto")}</td>
            </tr>
            <tr>
                <th>Generato</th>
                <td>{info.get("Scan", {}).get("Generated", "Sconosciuto")}</td>
            </tr>
        </table>
    </div>
    """

def generate_headers_section(result):
    """
    Genera la sezione delle intestazioni dell'email.
    
    Args:
        result: Risultato dell'analisi per una singola email
    
    Returns:
        Codice HTML della sezione intestazioni
    """
    if "Headers" not in result:
        return ""
    
    # Pulizia supplementare dei dati dell'header prima della visualizzazione
    if "HTML_View" in result["Headers"]:
        headers_html_view = {}
        for key, value in result["Headers"]["HTML_View"].items():
            if isinstance(value, str):
                clean_value = clean_text_for_html(value)
                clean_value = clean_value.strip()  # Rimuove spazi o newline all'inizio e alla fine
                headers_html_view[key] = clean_value
            else:
                headers_html_view[key] = value
        result["Headers"]["HTML_View"] = headers_html_view
    
    html = """
    <div class="section">
        <h2>Intestazioni</h2>
        <table style="table-layout:fixed; width:100%;">
            <colgroup>
                <col style="width:20%;" />
                <col style="width:80%;" />
            </colgroup>
            <tr>
                <th>Campo</th>
                <th>Valore</th>
            </tr>
    """
    
    for key, value in result["Headers"]["Headers"].items():
        formatted_value = format_email_field(key, value)
        
        html += f"""
            <tr>
                <td style="width:20%;">{escape(str(key))}</td>
                <td style="width:80%;">{formatted_value}</td>
            </tr>
        """
    
    html += """
        </table>
    </div>
    """
    
    return html

def generate_header_investigation_section(result):
    """
    Genera la sezione dell'analisi delle intestazioni dell'email.
    
    Args:
        result: Risultato dell'analisi per una singola email
    
    Returns:
        Codice HTML della sezione analisi intestazioni
    """
    if "Headers" not in result or "Investigation" not in result["Headers"]:
        return ""
    
    html = """
    <div class="section">
        <h2>Analisi Intestazioni</h2>
        <table>
            <tr>
                <th>Controllo</th>
                <th>Dettagli</th>
            </tr>
    """
    
    for check, details in result["Headers"]["Investigation"].items():
        details_html = ""
        for key, value in details.items():
            # Gestisce meglio i valori multiriga preservando le interruzioni di riga
            formatted_value = format_multiline_text_for_html(str(value))
            details_html += f"<strong>{key}:</strong> {formatted_value}<br>"
        
        html += f"""
            <tr>
                <td>{escape(str(check))}</td>
                <td>{details_html.strip()}</td>
            </tr>
        """
    
    html += """
        </table>
    </div>
    """
    
    return html

def generate_links_section(result):
    """
    Genera la sezione dei collegamenti dell'email.
    
    Args:
        result: Risultato dell'analisi per una singola email
    
    Returns:
        Codice HTML della sezione collegamenti
    """
    if "Links" not in result or not result["Links"].get("Links"):
        return ""
        
    links = result["Links"]["Links"]
    has_investigation = "Investigation" in result["Links"] and result["Links"]["Investigation"]
    
    html = """
    <div class="section">
        <h2>Collegamenti ({count} trovati)</h2>
    """.format(count=result["Links"].get("Count", 0))
    
    if not links:
        html += """
        <div class="alert alert-info">
            Nessun collegamento trovato in questa email.
        </div>
        """
    else:
        if has_investigation:
            # Mostra tabella con risultati dell'analisi
            html += """
            <table class="table">
                <tr>
                    <th style="width: 60%">URL</th>
                    <th style="width: 20%">Stato</th>
                    <th style="width: 20%">Dettagli</th>
                </tr>
            """
            
            for data in result["Links"]["Investigation"]:
                url = data["URL"]
                analysis = data["Analysis"]
                safe = analysis.get("Safe", False)
                detections = analysis.get("Detections", 0)
                vt_link = analysis.get("VirusTotal", "")
                error = analysis.get("Error", "")
                
                status_class = "success" if safe else "danger"
                status_text = "Sicuro" if safe else "Non sicuro"
                if error:
                    status_class = "warning"
                    status_text = "Non verificato"
                
                html += f"""
                <tr>
                    <td>
                        <a href="{escape(url)}" target="_blank" rel="noopener noreferrer">
                            {escape(url)}
                        </a>
                    </td>
                    <td>
                        <span class="badge badge-{status_class}">{status_text}</span>
                    </td>
                    <td>
                """
                
                if error:
                    html += f'<span class="text-warning">{escape(error)}</span>'
                else:
                    html += f"""
                        <strong>Rilevamenti:</strong> {detections}<br>
                        <a href="{escape(vt_link)}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline-secondary">
                            VirusTotal <i class="fa fa-external-link-alt"></i>
                        </a>
                    """
                
                html += """
                    </td>
                </tr>
                """
            
            html += "</table>"
        else:
            # Mostra lista semplice di link
            html += """
            <table class="table">
                <tr>
                    <th>URL</th>
                </tr>
            """
            
            for link in links:
                formatted_link = format_multiline_text_for_html(str(link))
                html += f"""
                <tr>
                    <td>
                        <a href="{escape(link)}" target="_blank" rel="noopener noreferrer">
                            {formatted_link}
                        </a>
                    </td>
                </tr>
                """
                
            html += "</table>"
    
    html += """
    </div>
    """
    
    return html

def generate_links_section(links_data):
    """
    Genera la sezione per l'analisi dei collegamenti, includendo sia i risultati di base che quelli di investigazione.
    
    Args:
        links_data: Dizionario contenente i risultati dell'analisi dei collegamenti
        
    Returns:
        Stringa HTML per la sezione dei collegamenti
    """
    if not links_data or not links_data.get("unique_links"):
        return "<div class='section'><h3>Analisi Collegamenti</h3><p>Nessun collegamento trovato in questa email.</p></div>"
        
    html = [
        "<div class='section'>",
        "<h3>Analisi Collegamenti</h3>",
        f"<p>Totale collegamenti unici trovati: {links_data['total_links']}</p>",
        "<div class='link-list'>"
    ]
    
    # Mostra i collegamenti con la loro analisi
    for link_data in links_data["unique_links"]:
        url = escape(link_data["url"])
        domain = escape(link_data["domain"])
        
        # Determina la classe di sicurezza del collegamento se esistono risultati di investigazione
        link_class = "link-item"
        safety_info = ""
        if links_data.get("investigation_results"):
            safety_score = link_data.get("safety_score", 0)
            if safety_score >= 80:
                link_class += " safe-link"
            elif safety_score >= 50:
                link_class += " warning-link"
            else:
                link_class += " danger-link"
                
            threats = link_data.get("threats", [])
            if threats:
                safety_info = f"<div class='threat-info'>Minacce: {', '.join(escape(t) for t in threats)}</div>"
            
            safety_info = f"""
                <div class='safety-score'>
                    Punteggio di Sicurezza: {safety_score}%
                    {safety_info}
                </div>
            """
        
        html.append(f"""
            <div class='{link_class}'>
                <div class='link-url'>
                    <a href='{url}' target='_blank' rel='noopener noreferrer'>{url}</a>
                </div>
                <div class='link-details'>
                    <span class='domain-info'>Dominio: {domain}</span>
                    {safety_info}
                </div>
            </div>
        """)
    
    html.extend([
        "</div>",  # chiudi link-list
        "</div>"   # chiudi sezione
    ])
    
    return "\n".join(html)

def generate_attachments_section(result):
    """
    Genera la sezione degli allegati dell'email.
    
    Args:
        result: Risultato dell'analisi per una singola email
    
    Returns:
        Codice HTML della sezione allegati
    """
    if "Attachments" not in result or "Attachments" not in result["Attachments"]:
        return ""
    
    attachments = result["Attachments"]["Attachments"]
    has_attachments = "Allegati" in attachments and bool(attachments["Allegati"])
    
    html = """
    <div class="section">
        <h2>Allegati</h2>
    """

    # Avviso generale sugli allegati
    if "Avviso" in attachments:
        alert_class = "alert-warning" if "ATTENZIONE" in attachments["Avviso"] else "alert-info"
        html += f"""
        <div class="alert {alert_class}">
            {escape(attachments["Avviso"])}
        </div>
        """
    
    if not has_attachments:
        html += """
        <div class="alert alert-info">
            Nessun allegato trovato in questa email.
        </div>
        </div>
        """
        return html
    
    html += """
        <table>
            <tr>
                <th>Nome File</th>
                <th>Tipo</th>
                <th>Dimensione</th>
                <th>Stato</th>
                <th>Hash</th>
            </tr>
    """
    
    for _, attachment in attachments["Allegati"].items():
        # Nome file e percorso
        filename = attachment["Filename"]
        if "File Path" in attachment:
            filename = f'<a href="{escape(attachment["File Path"])}">{escape(filename)}</a>'
        else:
            filename = escape(filename)
        
        # Tipo MIME e dimensione
        mime_type = escape(attachment["MIME Type"])
        size = escape(attachment["Size"])
        
        # Stato di sicurezza
        is_suspicious = attachment["Sospetto"] == "Sì - File eseguibile (.exe/.bat)"
        status_class = "danger" if is_suspicious else "success"
        status_text = escape(attachment["Sospetto"])
        
        # Hash con link a VirusTotal
        hash_html = f"""
            <details>
                <summary>Mostra hash</summary>
                <small>
                    <strong>MD5:</strong> <a href="https://www.virustotal.com/gui/file/{attachment["MD5"]}" target="_blank">{attachment["MD5"]}</a><br>
                    <strong>SHA1:</strong> <a href="https://www.virustotal.com/gui/file/{attachment["SHA1"]}" target="_blank">{attachment["SHA1"]}</a><br>
                    <strong>SHA256:</strong> <a href="https://www.virustotal.com/gui/file/{attachment["SHA256"]}" target="_blank">{attachment["SHA256"]}</a>
                </small>
            </details>
        """
        
        html += f"""
            <tr>
                <td>{filename}</td>
                <td>{mime_type}</td>
                <td>{size}</td>
                <td><span class="badge badge-{status_class}">{status_text}</span></td>
                <td>{hash_html}</td>
            </tr>
        """
    
    html += """
        </table>
    </div>
    """
    
    return html

def generate_hashes_section(result):
    """
    Genera la sezione delle impronte hash dell'email.
    
    Args:
        result: Risultato dell'analisi per una singola email
    
    Returns:
        Codice HTML della sezione hash
    """
    if "Hashes" not in result:
        return ""
    
    hashes = result["Hashes"].get("Hashes", {})
    if not hashes:
        return ""
        
    html = """
    <div class="section">
        <h2>Impronte</h2>
        <table>
            <tr>
                <th>Algoritmo</th>
                <th>Hash</th>
            </tr>
    """
    
    for hash_type, hash_value in hashes.items():
        html += f"""
            <tr>
                <td>{escape(str(hash_type))}</td>
                <td><code>{escape(str(hash_value))}</code></td>
            </tr>
        """
    
    html += """
        </table>
    </div>
    """
    
    return html

###############################################################################
# FUNZIONI PRINCIPALI PER L'OUTPUT HTML
###############################################################################

def generate_email_analysis_html(result):
    """
    Genera HTML per una singola analisi email utilizzando le funzioni separate per ogni sezione.
    
    Args:
        result: Risultato dell'analisi per una singola email
        
    Returns:
        Contenuto HTML come stringa
    """
    html = ""
    
    # Aggiunge ogni sezione dell'analisi
    html += generate_information_section(result)
    html += generate_headers_section(result)
    html += generate_header_investigation_section(result)
    html += generate_links_section(result)
    html += generate_attachments_section(result)
    html += generate_hashes_section(result)
    
    return html

def is_email_suspicious(result):
    """
    Determina se un'email è sospetta in base ai risultati dell'analisi.
    
    Args:
        result: Risultato dell'analisi per una singola email
        
    Returns:
        Booleano che indica se l'email è sospetta
    """
    suspicious = False
    
    # Controllo per intestazioni sospette
    if "Headers" in result and "Investigation" in result["Headers"]:
        for name, data in result["Headers"]["Investigation"].items():
            if "Suspicious" in data and data["Suspicious"] == "Yes":
                suspicious = True
                break
                
    # Controllo per collegamenti sospetti
    if "Links" in result and "Investigation" in result["Links"]:
        if len(result["Links"]["Investigation"]) > 0:
            suspicious = True
            
    # Controllo per allegati sospetti
    if "Attachments" in result and "Investigation" in result["Attachments"]:
        if len(result["Attachments"]["Investigation"]) > 0:
            suspicious = True
    
    return suspicious

def generate_css_styles():
    """
    Genera il CSS per lo stile della pagina HTML.
    
    Returns:
        Stringa contenente il CSS
    """
    return get_base_styles()

def generate_javascript():
    """
    Genera il JavaScript per l'interattività della pagina HTML.
    
    Returns:
        Stringa contenente il JavaScript
    """
    return """
    <script>
        function showEmail(index) {
            // Hide all email contents
            document.querySelectorAll('.email-content').forEach(el => {
                el.classList.remove('active');
            });
            
            // Remove active class from all cards
            document.querySelectorAll('.email-card').forEach(el => {
                el.classList.remove('active');
            });
            
            // Show selected email content
            document.getElementById(`email-${index}`).classList.add('active');
            
            // Add active class to selected card
            document.querySelectorAll('.email-card')[index].classList.add('active');
        }
    </script>
    """

def generate_email_selection_interface(analysis_results):
    """
    Genera un'interfaccia HTML per selezionare quale analisi email visualizzare.
    
    Args:
        analysis_results: Lista dei risultati dell'analisi per ogni email
        
    Returns:
        Contenuto HTML come stringa
    """
    html = f"""
    <!DOCTYPE html>
    <html lang="it">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Analisi Email</title>
        {generate_css_styles()}
    </head>
    <body>
        <div class="container">
            <h1>Risultati Analisi Email</h1>
            <p>Clicca su un'email per visualizzarne l'analisi. Le email con bordi rossi sono sospette.</p>
            
            <div class="email-list">
    """
    
    # Genera le card di selezione delle email
    for i, result in enumerate(analysis_results):
        email_file = result.get("Information", {}).get("Scan", {}).get("Filename", f"Email {i+1}")
        filename = os.path.basename(email_file)
        is_suspicious = is_email_suspicious(result)
        suspicious_class = "suspicious" if is_suspicious else ""
        suspicious_badge = '<span class="badge">SOSPETTA</span>' if is_suspicious else ""
        
        html += f"""
            <div class="email-card {suspicious_class}" onclick="showEmail({i})">
                <h3>{filename} {suspicious_badge}</h3>
                <p>Clicca per vedere l'analisi</p>
            </div>
        """
    
    html += """
            </div>
            
            <div id="email-details">
    """
    
    # Genera il contenuto dell'analisi individuale delle email
    for i, result in enumerate(analysis_results):
        active_class = "active" if i == 0 else ""
        html += f"""
            <div id="email-{i}" class="email-content {active_class}">
                {generate_email_analysis_html(result)}
            </div>
        """
    
    html += f"""
            </div>
        </div>
        
        {generate_javascript()}
    </body>
    </html>
    """
    
    return html

def generate_html_output(analysis_results, output_filename):
    """
    Genera un file HTML di output dai risultati dell'analisi.
    
    Args:
        analysis_results: Lista dei risultati dell'analisi per ogni email
        output_filename: Nome del file di output
        
    Returns:
        Percorso del file di output
    """
    # Assicura che la directory di output esista
    output_dir = os.path.dirname(output_filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Crea l'HTML con l'interfaccia di selezione delle email
    html_content = generate_email_selection_interface(analysis_results)
    
    # Scrive il contenuto nel file di output
    with open(output_filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_filename

def format_results_for_html(result):
    """
    Formatta i risultati dell'analisi per l'output HTML.
    
    Args:
        result: Risultato dell'analisi per una singola email
        
    Returns:
        Dati formattati per la generazione HTML
    """
    formatted = {}
    
    # Formatta dati delle intestazioni
    if "Headers" in result:
        formatted["Headers"] = result["Headers"]["Headers"]
    
    # Formatta dati dei collegamenti
    if "Links" in result:
        formatted["Links"] = result["Links"]["Links"]
    
    # Formatta dati degli allegati
    if "Attachments" in result:
        formatted["Attachments"] = result["Attachments"]["Attachments"]
    
    # Formatta dati delle impronte
    if "Hashes" in result:
        formatted["Digests"] = result["Hashes"]["Hashes"]
    
    return formatted

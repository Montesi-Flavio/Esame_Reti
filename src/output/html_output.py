"""
HTML output generation functionality.
"""

import os
import re
import email.header
from html_generator import generate_table_from_json
from datetime import datetime
import json
from html import escape

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
    
    # Sostituisce singoli newline con spazi
    text = text.replace('\n', ' ').strip()
    
    # Rimuove spazi multipli
    text = re.sub(r'\s+', ' ', text)
    
    # Rimuove Mostra Altri Header e altre stringhe di controllo comuni
    text = re.sub(r'Mostra Altri Header', '', text)
    
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

def generate_html_output(analysis_results, output_filename):
    """
    Generate an HTML output file from analysis results.
    
    Args:
        analysis_results: List of analysis results for each email
        output_filename: Name of the output file
        
    Returns:
        Path to the output file
    """
    # Ensure the output directory exists
    output_dir = os.path.dirname(output_filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create HTML with email selection interface
    html_content = generate_email_selection_interface(analysis_results)
    
    # Write the content to the output file
    with open(output_filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_filename

def is_email_suspicious(result):
    """
    Determine if an email is suspicious based on analysis results.
    
    Args:
        result: Analysis result for a single email
        
    Returns:
        Boolean indicating if the email is suspicious
    """
    suspicious = False
    
    # Check for suspicious headers
    if "Headers" in result and "Investigation" in result["Headers"]:
        for name, data in result["Headers"]["Investigation"].items():
            if "Suspicious" in data and data["Suspicious"] == "Yes":
                suspicious = True
                break
                
    # Check for suspicious links
    if "Links" in result and "Investigation" in result["Links"]:
        if len(result["Links"]["Investigation"]) > 0:
            suspicious = True
            
    # Check for suspicious attachments
    if "Attachments" in result and "Investigation" in result["Attachments"]:
        if len(result["Attachments"]["Investigation"]) > 0:
            suspicious = True
    
    return suspicious

def generate_email_selection_interface(analysis_results):
    """
    Generate an HTML interface for selecting which email analysis to view.
    
    Args:
        analysis_results: List of analysis results for each email
        
    Returns:
        HTML content as a string
    """
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Analysis</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                overflow-x: hidden; /* Previeni lo scroll orizzontale */
            }
            .container {
                width: 100%;
                max-width: 1920px;
                margin: 0 auto;
                padding: 20px;
                box-sizing: border-box;
            }
            .email-list {
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin-bottom: 30px;
                justify-content: flex-start;
            }
            .email-card {
                border: 2px solid #ccc;
                border-radius: 5px;
                padding: 15px;
                width: calc(25% - 15px); /* Responsive card width */
                min-width: 200px;
                max-width: 300px;
                cursor: pointer;
                transition: all 0.3s ease;
                box-sizing: border-box;
                margin-bottom: 10px;
                flex-grow: 0;
                flex-shrink: 0;
            }
            .email-card.suspicious {
                border-color: #ff0000;
            }
            .email-card:hover {
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }
            .email-card.active {
                background-color: #f0f0f0;
                border-color: #007bff;
            }
            .email-content {
                display: none;
                border: 1px solid #ddd;
                padding: 20px;
                border-radius: 5px;
                overflow-x: auto; /* Aggiungi scrollbar orizzontale se necessario */
            }
            .email-content.active {
                display: block;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
                table-layout: fixed; /* Previeni l'espansione infinita delle celle */
            }
            table, th, td {
                border: 1px solid #ddd;
            }
            /* Applica stili più specifici per le celle */
            table th, table td {
                padding: 10px;
                text-align: left;
                word-wrap: break-word; /* Permette alle parole lunghe di andare a capo */
                overflow-wrap: break-word;
            }
            /* Regole con priorità aumentata usando !important */
            table th {
                background-color: #f2f2f2;
                width: 20% !important; /* Forza l'applicazione della larghezza */
                max-width: 20% !important;
            }
            table td {
                width: 80% !important; /* Forza l'applicazione della larghezza */
                min-width: 80% !important;
            }
            .section {
                margin-bottom: 30px;
            }
            .section h2 {
                text-align: center;
                margin-bottom: 15px;
            }
            .badge {
                background-color: #dc3545;
                color: white;
                padding: 3px 8px;
                border-radius: 10px;
                font-size: 12px;
                margin-left: 5px;
            }
            /* Media query per dispositivi mobili */
            @media (max-width: 768px) {
                .email-card {
                    width: calc(50% - 15px);
                }
                th, td {
                    padding: 8px 5px;
                }
            }
            @media (max-width: 480px) {
                .email-card {
                    width: 100%;
                }
                th {
                    width: 40%;
                }
                td {
                    width: 60%;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Email Analysis Results</h1>
            <p>Click on an email to view its analysis. Emails with red borders are suspicious.</p>
            
            <div class="email-list">
    """
    
    # Generate email selection cards
    for i, result in enumerate(analysis_results):
        email_file = result.get("Information", {}).get("Scan", {}).get("Filename", f"Email {i+1}")
        filename = os.path.basename(email_file)
        is_suspicious = is_email_suspicious(result)
        suspicious_class = "suspicious" if is_suspicious else ""
        suspicious_badge = '<span class="badge">SUSPICIOUS</span>' if is_suspicious else ""
        
        html += f"""
            <div class="email-card {suspicious_class}" onclick="showEmail({i})">
                <h3>{filename} {suspicious_badge}</h3>
                <p>Click to view analysis</p>
            </div>
        """
    
    html += """
            </div>
            
            <div id="email-details">
    """
    
    # Generate individual email analysis content
    for i, result in enumerate(analysis_results):
        active_class = "active" if i == 0 else ""
        html += f"""
            <div id="email-{i}" class="email-content {active_class}">
                {generate_email_analysis_html(result)}
            </div>
        """
    
    html += """
            </div>
        </div>
        
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
    </body>
    </html>
    """
    
    return html

def generate_email_analysis_html(result):
    """
    Generate HTML for a single email analysis.
    
    Args:
        result: Analysis result for a single email
        
    Returns:
        HTML content as a string
    """
    html = ""
    
    # Information section
    if "Information" in result:
        info = result["Information"]
        html += """
        <div class="section">
            <h2>Information</h2>
            <table>
                <tr>
                    <th>Filename</th>
                    <td>{}</td>
                </tr>
                <tr>
                    <th>Generated</th>
                    <td>{}</td>
                </tr>
            </table>
        </div>
        """.format(
            info.get("Scan", {}).get("Filename", "Unknown"),
            info.get("Scan", {}).get("Generated", "Unknown")
        )
    
    # Headers section
    if "Headers" in result:
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
        
        html += """
        <div class="section">
            <h2>Headers</h2>
            <table style="table-layout:fixed; width:100%;">
                <colgroup>
                    <col style="width:20%;" />
                    <col style="width:80%;" />
                </colgroup>
                <tr>
                    <th>Field</th>
                    <th>Value</th>
                </tr>
        """
        
        for key, value in result["Headers"]["Headers"].items():
            raw_value = str(value)
            decoded_value = decode_header_value(raw_value)
            clean_value = clean_text_for_html(decoded_value).strip()
            formatted_value = clean_value
            
            if "from" in key.lower() or "received" in key.lower() or "by" in key.lower():
                for separator in ["by ", "from ", "for ", "with ", "id ", "; "]:
                    if separator in formatted_value:
                        formatted_value = formatted_value.replace(separator, "<br>" + separator)
                if "received" in key.lower():
                    formatted_value = formatted_value.replace("[", "<br>[").replace("(", "<br>(")
            
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
        
        if "Investigation" in result["Headers"]:
            html += """
            <div class="section">
                <h2>Headers Investigation</h2>
                <table>
                    <tr>
                        <th>Check</th>
                        <th>Details</th>
                    </tr>
            """
            
            for check, details in result["Headers"]["Investigation"].items():
                details_html = ""
                for key, value in details.items():
                    details_html += f"<strong>{key}:</strong> {escape(str(value))}<br>"
                
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
    
    # Links section
    if "Links" in result:
        html += """
        <div class="section">
            <h2>Links</h2>
            <table>
                <tr>
                    <th>Link</th>
                </tr>
        """
        
        for link in result["Links"]["Links"]:
            html += f"""
                <tr>
                    <td>{escape(str(link))}</td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        """
    
    # Attachments section
    if "Attachments" in result:
        html += """
        <div class="section">
            <h2>Attachments</h2>
            <table>
                <tr>
                    <th>Filename</th>
                    <th>Type</th>
                    <th>Size</th>
                </tr>
        """
        
        attachments = result["Attachments"].get("Attachments", {})
        
        if isinstance(attachments, list) and attachments:
            for attachment in attachments:
                if isinstance(attachment, dict):
                    filename = attachment.get('filename', 'Unknown')
                    content_type = attachment.get('content_type', 'Unknown') or attachment.get('mime_type', 'Unknown')
                    size = attachment.get('size', 'Unknown')
                else:
                    filename = str(attachment)
                    content_type = 'Unknown'
                    size = 'Unknown'
                
                html += f"""
                    <tr>
                        <td>{escape(str(filename))}</td>
                        <td>{escape(str(content_type))}</td>
                        <td>{escape(str(size))}</td>
                    </tr>
                """
        elif isinstance(attachments, dict) and attachments:
            for idx, attachment in attachments.items():
                if isinstance(attachment, dict):
                    filename = attachment.get('Filename', attachment.get('filename', 'Unknown'))
                    content_type = attachment.get('MIME Type', attachment.get('mime_type', 'Unknown'))
                    size = attachment.get('Size', attachment.get('size', 'Unknown'))
                    
                    html += f"""
                        <tr>
                            <td>{escape(str(filename))}</td>
                            <td>{escape(str(content_type))}</td>
                            <td>{escape(str(size))}</td>
                        </tr>
                    """
        else:
            html += f"""
                <tr>
                    <td colspan="3">No attachment information available</td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        """
    
    # Hashes section
    if "Hashes" in result:
        html += """
        <div class="section">
            <h2>Digests</h2>
            <table>
                <tr>
                    <th>Algorithm</th>
                    <th>Hash</th>
                </tr>
        """
        
        for hash_type, hash_value in result["Hashes"]["Hashes"].items():
            html += f"""
                <tr>
                    <td>{escape(str(hash_type))}</td>
                    <td>{escape(str(hash_value))}</td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        """
    
    return html

def format_results_for_html(result):
    """
    Format analysis results for HTML output.
    
    Args:
        result: Analysis result for a single email
        
    Returns:
        Formatted data for HTML generation
    """
    formatted = {}
    
    # Format headers data
    if "Headers" in result:
        formatted["Headers"] = result["Headers"]["Headers"]
    
    # Format links data
    if "Links" in result:
        formatted["Links"] = result["Links"]["Links"]
    
    # Format attachments data
    if "Attachments" in result:
        formatted["Attachments"] = result["Attachments"]["Attachments"]
    
    # Format hashes data
    if "Hashes" in result:
        formatted["Digests"] = result["Hashes"]["Hashes"]
    
    return formatted
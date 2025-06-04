"""
Attachment analysis functionality for email investigation.
"""

import os
import hashlib
import logging
import mimetypes  # Utilizziamo mimetypes invece di magic
from email import message_from_file
from email.message import EmailMessage
from connectors import check_hash_safety

# Configure logging
logger = logging.getLogger('email_analyzer.attachment_analyzer')

def is_executable_file(filename):
    """
    Controlla se il file è un eseguibile (.exe o .bat)
    
    Args:
        filename: Nome del file da controllare
        
    Returns:
        Bool: True se è un file eseguibile, False altrimenti
    """
    if not filename:
        return False
    
    # Controlla l'estensione del file (case insensitive)
    ext = os.path.splitext(filename.lower())[1]
    return ext in ['.exe', '.bat']

def get_mime_type(filename, content=None):
    """
    Determina il tipo MIME di un file basandosi sull'estensione.
    Fallback: application/octet-stream
    
    Args:
        filename: Nome del file
        content: Contenuto del file (non utilizzato in questa implementazione)
        
    Returns:
        Tipo MIME come stringa
    """
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type or 'application/octet-stream'

def extract_attachments(email_message, output_dir=None, email_id=None):
    """
    Extract all attachments from an email message.
    
    Args:
        email_message: Email message object
        output_dir: Directory to save attachments (optional)
        email_id: Identificativo della email di origine (optional)
        
    Returns:
        List of dictionaries with attachment information
    """
    attachments = []
    
    if not email_message.is_multipart():
        return attachments
        
    for part in email_message.walk():
        if part.get_content_disposition() == 'attachment':
            filename = part.get_filename()
            if not filename:
                filename = f"unknown_attachment_{len(attachments)}"
                
            content = part.get_payload(decode=True)
            mime_type = part.get_content_type() or get_mime_type(filename, content)
            file_size = len(content)
            
            # Calculate hash values
            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
            
            attachment_info = {
                "filename": filename,
                "mime_type": mime_type,
                "size": file_size,
                "md5": md5_hash,
                "sha1": sha1_hash,
                "sha256": sha256_hash
            }
            
            # Aggiungi l'ID dell'email di origine se disponibile
            if email_id:
                attachment_info["email_id"] = email_id
            
            # Save attachment to file if output directory is provided
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                
                # Crea un nome file che include l'id dell'email per evitare conflitti
                if email_id:
                    base_name, ext = os.path.splitext(filename)
                    # Usa una convenzione di denominazione che include l'ID dell'email
                    safe_filename = f"{base_name}_email_{email_id}{ext}"
                else:
                    safe_filename = filename
                
                file_path = os.path.join(output_dir, safe_filename)
                with open(file_path, 'wb') as f:
                    f.write(content)
                attachment_info["saved_path"] = file_path
                
                # Crea un file di mappatura che associa l'allegato all'email nella cartella log
                if email_id:
                    # Crea la cartella log se non esiste
                    log_dir = os.path.join(os.path.dirname(output_dir), "log")
                    os.makedirs(log_dir, exist_ok=True)
                    
                    # Percorso del file attachment_map.txt nella cartella log
                    map_file = os.path.join(log_dir, "attachment_map.txt")
                    
                    # Riga da aggiungere
                    map_line = f"{safe_filename} -> Email ID: {email_id}\n"
                    
                    # Controlla se il file esiste già
                    if os.path.exists(map_file):
                        # Leggi il contenuto attuale e verifica se la riga è già presente
                        with open(map_file, 'r', encoding='utf-8') as f:
                            existing_lines = f.readlines()
                        
                        # Aggiungi la riga solo se non è già presente
                        if map_line not in existing_lines:
                            with open(map_file, 'a', encoding='utf-8') as f:
                                f.write(map_line)
                    else:
                        # Se il file non esiste, crealo e scrivi la riga
                        with open(map_file, 'w', encoding='utf-8') as f:
                            f.write(map_line)
                
            attachments.append(attachment_info)
            
    return attachments

def analyze_attachments(email_file, investigation=False, save_attachments=False, output_dir=None):
    """
    Analyze attachments in an email file.
    
    Args:
        email_file: Path to the email file
        investigation: Whether to perform security investigation
        save_attachments: Whether to save attachments to disk
        output_dir: Directory to save attachments
        
    Returns:
        Dictionary with attachment data and investigation results
    """
    # Estrai l'ID dell'email dal nome del file
    email_id = os.path.basename(email_file).split('.')[0]
    
    # Parse email usando un approccio binario per garantire la lettura corretta degli allegati
    try:
        # Prima prova con la lettura binaria che preserva gli allegati binari
        from email import message_from_binary_file
        from email.parser import BytesParser, Parser
        
        with open(email_file, 'rb') as f:
            # Usa BytesParser per gestire i contenuti binari, molto più affidabile per gli allegati
            email_message = BytesParser().parse(f)
    except Exception as e:
        # Fallback al vecchio metodo in caso di errore
        print(f"Errore nella lettura binaria dell'email {email_file}: {e}")
        print("Tentativo con il metodo alternativo...")
        with open(email_file, 'r', encoding='utf-8', errors='ignore') as f:
            email_message = message_from_file(f)
    
    # Extract attachments
    attachments_dir = os.path.join(output_dir, "attachments") if output_dir and save_attachments else None
    attachments = extract_attachments(
        email_message, 
        attachments_dir if save_attachments else None,
        email_id  # Passa l'ID dell'email
    )
    
    # Format data
    attachment_data = {}
    suspicious_files_found = False
    
    for idx, attachment in enumerate(attachments, 1):
        # Verifica se il file è sospetto basandosi sull'estensione
        is_executable = is_executable_file(attachment["filename"])
        if is_executable:
            suspicious_files_found = True
            
        # Base data
        attachment_info = {
            "Filename": attachment["filename"],
            "MIME Type": attachment["mime_type"],
            "Size": f"{attachment['size']} bytes",
            "MD5": attachment["md5"],
            "SHA1": attachment["sha1"],
            "SHA256": attachment["sha256"],
            "Sospetto": "Sì - File eseguibile (.exe/.bat)" if is_executable else "No",
            "Email ID": email_id  # Aggiungi l'ID dell'email ai risultati
        }
        
        # Aggiungi il percorso del file salvato se disponibile
        if "saved_path" in attachment:
            attachment_info["File Path"] = attachment["saved_path"]
        
        # Aggiungi dettagli di sicurezza se richiesta un'indagine
        if investigation:
            is_safe = True
            security_details = []
            
            # Controllo di sicurezza basato sull'estensione
            if is_executable:
                security_details.append("File eseguibile rilevato (.exe o .bat) - Alto rischio di malware")
                is_safe = False
              # Controllo hash con VirusTotal
            vt_results = {}
            html_formatted_results = {}
            quota_exceeded = False
            
            for hash_type, hash_value in [("MD5", attachment["md5"]), 
                                         ("SHA1", attachment["sha1"]), 
                                         ("SHA256", attachment["sha256"])]:
                safe, positives, error = check_hash_safety(hash_value)
                
                if error:
                    if "QuotaExceeded" in error:
                        logger.warning(f"VirusTotal API quota exceeded for {hash_type} hash check")
                        quota_exceeded = True
                        # Continue checking other hashes in case quota resets
                        continue
                    else:
                        logger.error(f"Error checking {hash_type} hash: {error}")
                        continue
                  # Process successful result
                vt_link = f"https://www.virustotal.com/gui/file/{hash_value}"
                if not safe:
                    is_safe = False
                    security_details.append(f"Rilevato da VirusTotal: {positives} positivi")
                    suspicious_files_found = True
                
                vt_results[hash_type] = {
                    "Link": vt_link,
                    "Positives": positives
                }
                
                # Creazione di una versione formattata per HTML
                html_formatted_results[hash_type] = {
                    "Tipo": hash_type,
                    "Valore": hash_value,
                    "Link VirusTotal": f'<a href="{vt_link}" target="_blank">Verifica su VirusTotal</a>',
                    "Rilevamenti": f"{positives} positivi" if not safe else "Nessun rilevamento"
                }
            
            # Add quota exceeded warning if it occurred
            if quota_exceeded:
                security_details.append("VirusTotal API quota exceeded - Some hash checks unavailable")
            
            # Aggiorna lo stato di sicurezza generale
            security_status = "Sicuro - Nessuna minaccia rilevata" if (is_safe and not is_executable) else "Non sicuro - Potenziale minaccia"
            
            attachment_info["Stato Sicurezza"] = security_status
            if not is_safe or is_executable:
                attachment_info["Dettagli Sicurezza"] = security_details
            
            if vt_results:
                attachment_info["VirusTotal"] = vt_results
                attachment_info["HTML_Formatted"] = html_formatted_results
        
        # Crea una versione formattata per HTML dell'attachment info
        html_info = {
            "Nome File": attachment_info["Filename"],
            "Tipo MIME": attachment_info["MIME Type"],
            "Dimensione": attachment_info["Size"],
            "Hash MD5": f'<code>{attachment_info["MD5"]}</code>',
            "Hash SHA1": f'<code>{attachment_info["SHA1"]}</code>',
            "Hash SHA256": f'<code>{attachment_info["SHA256"]}</code>',
            "Stato": f'<span class="badge badge-{is_executable and "danger" or "success"}">{attachment_info["Sospetto"]}</span>',
            "Email di origine": f'<strong>Email {attachment_info["Email ID"]}.eml</strong>'
        }
        
        # Aggiungi stato di sicurezza se presente
        if "Stato Sicurezza" in attachment_info:
            safety_class = "success" if "Sicuro" in attachment_info["Stato Sicurezza"] else "danger"
            html_info["Sicurezza"] = f'<span class="badge badge-{safety_class}">{attachment_info["Stato Sicurezza"]}</span>'
            
            if "Dettagli Sicurezza" in attachment_info:
                details_html = "<ul>"
                for detail in attachment_info["Dettagli Sicurezza"]:
                    details_html += f"<li>{detail}</li>"
                details_html += "</ul>"
                html_info["Dettagli"] = details_html
        
        # Aggiungi il percorso se disponibile
        if "File Path" in attachment_info:
            relative_path = os.path.basename(attachment_info["File Path"])
            html_info["File Salvato"] = f'<a href="attachments/{relative_path}">{relative_path}</a>'
        
        # Inserisci le informazioni HTML formattate
        attachment_info["HTML_View"] = html_info
        
        attachment_data[str(idx)] = attachment_info
    
    result = {
        "Allegati": attachment_data,
        "Email ID": email_id  # Aggiungi l'ID dell'email anche ai risultati generali
    }
    
    # Se sono stati salvati allegati, crea un indice HTML
    if save_attachments and attachments_dir and attachments:
        index_path = create_attachment_index(attachments_dir)
        if index_path:
            result["Indice Allegati"] = index_path
    
    # Aggiungi un avviso generale se sono stati trovati file sospetti
    if suspicious_files_found:
        result["Avviso"] = "ATTENZIONE: Sono stati rilevati file potenzialmente pericolosi negli allegati."
    elif len(attachment_data) == 0:
        result["Avviso"] = "Nessun allegato trovato nell'email."
    else:
        result["Avviso"] = "Nessun file sospetto rilevato negli allegati."
    
    return result

def create_attachment_index(attachments_dir):
    """
    Crea un indice HTML degli allegati che mostra quali email contengono quali allegati.
    
    Args:
        attachments_dir: Directory dove sono stati salvati gli allegati
        
    Returns:
        Path del file indice HTML creato
    """
    if not os.path.exists(attachments_dir):
        return None
    
    # Crea un dizionario per mappare gli allegati alle email
    email_to_attachments = {}
    attachment_to_email = {}
    
    # Esamina tutti i file nella directory degli allegati
    for filename in os.listdir(attachments_dir):
        if filename == "attachment_index.html":
            continue
        
        # Estrai l'ID dell'email dal nome del file (basato sul pattern nome_email_ID.ext)
        parts = filename.split('_email_')
        if len(parts) > 1:
            base_name = parts[0]
            email_id = parts[1].split('.')[0]
            
            # Aggiorna le mappature
            if email_id not in email_to_attachments:
                email_to_attachments[email_id] = []
            
            email_to_attachments[email_id].append(filename)
            attachment_to_email[filename] = email_id
    
    # Crea un file HTML con l'indice
    index_path = os.path.join(attachments_dir, "attachment_index.html")
    
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Indice degli Allegati</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .email-section { 
            margin-bottom: 20px; 
            border: 1px solid #ddd; 
            padding: 10px; 
            border-radius: 5px; 
        }
        .email-header { 
            background-color: #f0f0f0; 
            padding: 8px; 
            margin-bottom: 10px; 
            font-weight: bold; 
        }
        .attachment-item { 
            margin: 5px 0; 
            padding: 5px; 
            background-color: #f9f9f9; 
        }
        a { color: #0066cc; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .attachment-list { margin-left: 20px; }
    </style>
</head>
<body>
    <h1>Indice degli Allegati Email</h1>
""")
        
        # Sezione per email
        f.write("<h2>Allegati raggruppati per Email</h2>")
        for email_id, attachments in sorted(email_to_attachments.items()):
            f.write(f'<div class="email-section">')
            f.write(f'<div class="email-header">Email: {email_id}.eml</div>')
            f.write(f'<div class="attachment-list">')
            
            for attachment in attachments:
                original_name = attachment.split('_email_')[0]
                path = os.path.join(".", attachment)
                f.write(f'<div class="attachment-item"><a href="{path}">{original_name}</a></div>')
            
            f.write('</div></div>')
        
        # Sezione per allegati
        f.write("<h2>Elenco completo degli Allegati</h2>")
        f.write('<ul>')
        for attachment, email_id in sorted(attachment_to_email.items()):
            original_name = attachment.split('_email_')[0]
            path = os.path.join(".", attachment)
            f.write(f'<li><a href="{path}">{original_name}</a> - da <strong>Email {email_id}.eml</strong></li>')
        f.write('</ul>')
        
        f.write("""
</body>
</html>
""")
    
    return index_path
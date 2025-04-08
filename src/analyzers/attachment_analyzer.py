"""
Attachment analysis functionality for email investigation.
"""

import os
import hashlib
import mimetypes  # Utilizziamo mimetypes invece di magic
from email import message_from_file
from email.message import EmailMessage
from connectors import check_hash_safety

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

def extract_attachments(email_message, output_dir=None):
    """
    Extract all attachments from an email message.
    
    Args:
        email_message: Email message object
        output_dir: Directory to save attachments (optional)
        
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
            
            # Save attachment to file if output directory is provided
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                file_path = os.path.join(output_dir, filename)
                with open(file_path, 'wb') as f:
                    f.write(content)
                attachment_info["saved_path"] = file_path
                
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
    # Parse email
    with open(email_file, 'r', encoding='utf-8', errors='ignore') as f:
        email_message = message_from_file(f)
    
    # Extract attachments
    attachments_dir = os.path.join(output_dir, "attachments") if output_dir and save_attachments else None
    attachments = extract_attachments(email_message, attachments_dir if save_attachments else None)
    
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
            "Sospetto": "Sì - File eseguibile (.exe/.bat)" if is_executable else "No"
        }
        
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
            for hash_type, hash_value in [("MD5", attachment["md5"]), 
                                         ("SHA1", attachment["sha1"]), 
                                         ("SHA256", attachment["sha256"])]:
                safe, positives, error = check_hash_safety(hash_value)
                
                if not error:
                    vt_link = f"https://www.virustotal.com/gui/file/{hash_value}"
                    if not safe:
                        is_safe = False
                        security_details.append(f"Rilevato da VirusTotal: {positives} positivi")
                        suspicious_files_found = True
                    
                    vt_results[hash_type] = {
                        "Link": vt_link,
                        "Positives": positives
                    }
            
            # Aggiorna lo stato di sicurezza generale
            if is_safe and not is_executable:
                attachment_info["Stato Sicurezza"] = "Sicuro - Nessuna minaccia rilevata"
            else:
                attachment_info["Stato Sicurezza"] = "Non sicuro - Potenziale minaccia"
                attachment_info["Dettagli Sicurezza"] = security_details
            
            if vt_results:
                attachment_info["VirusTotal"] = vt_results
        
        attachment_data[str(idx)] = attachment_info
    
    result = {"Allegati": attachment_data}
    
    # Aggiungi un avviso generale se sono stati trovati file sospetti
    if suspicious_files_found:
        result["Avviso"] = "ATTENZIONE: Sono stati rilevati file potenzialmente pericolosi negli allegati."
    elif len(attachment_data) == 0:
        result["Avviso"] = "Nessun allegato trovato nell'email."
    else:
        result["Avviso"] = "Nessun file sospetto rilevato negli allegati."
    
    return result
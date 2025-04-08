"""
Attachment analysis functionality for email investigation.
"""

import os
import hashlib
import mimetypes  # Utilizziamo mimetypes invece di magic
from email import message_from_file
from email.message import EmailMessage
from connectors import check_hash_safety

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
    for idx, attachment in enumerate(attachments, 1):
        attachment_data[str(idx)] = {
            "Filename": attachment["filename"],
            "MIME Type": attachment["mime_type"],
            "Size": f"{attachment['size']} bytes",
            "MD5": attachment["md5"],
            "SHA1": attachment["sha1"],
            "SHA256": attachment["sha256"]
        }
    
    # Perform investigation if requested
    investigation_data = {}
    if investigation and attachments:
        for idx, attachment in enumerate(attachments, 1):
            investigation_data[str(idx)] = {}
            
            # Check file hash against VirusTotal
            for hash_type, hash_value in [("MD5", attachment["md5"]), 
                                         ("SHA1", attachment["sha1"]), 
                                         ("SHA256", attachment["sha256"])]:
                safe, positives, error = check_hash_safety(hash_value)
                
                if error:
                    investigation_data[str(idx)][hash_type] = {
                        "Error": error
                    }
                else:
                    investigation_data[str(idx)][hash_type] = {
                        "Virustotal": f"https://www.virustotal.com/gui/file/{hash_value}",
                        "Safety": "Safe" if safe else "Unsafe",
                        "Positives": positives
                    }
    
    return {"Data": attachment_data, "Investigation": investigation_data}
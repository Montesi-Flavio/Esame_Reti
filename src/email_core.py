"""
Core email fetching and processing functionality.
"""

import imaplib
import os
from email.parser import BytesParser
from email.policy import default
import re
from config import EMAIL_SERVER, EMAIL_USER, EMAIL_PASSWORD, DEFAULT_MAILBOX, DEFAULT_OUTPUT_DIR, LINK_REGEX

def fetch_emails(imap_server=EMAIL_SERVER, email_user=EMAIL_USER, email_pass=EMAIL_PASSWORD, 
                mailbox=DEFAULT_MAILBOX, output_dir=DEFAULT_OUTPUT_DIR):
    """
    Fetch emails from an IMAP server and save them as EML files.
    
    Args:
        imap_server: IMAP server address
        email_user: Email username
        email_pass: Email password
        mailbox: Mailbox to fetch from
        output_dir: Directory to save email files
        
    Returns:
        List of email file paths
    """
    email_files = []
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_user, email_pass)
        mail.select(mailbox)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        result, data = mail.search(None, "ALL")
        if result != "OK":
            print("Error fetching emails.")
            return email_files

        email_ids = data[0].split()
        for email_id in email_ids:
            result, msg_data = mail.fetch(email_id, "(BODY.PEEK[])")
            if result != "OK":
                continue
            raw_email = msg_data[0][1]
            eml_filename = os.path.join(output_dir, f"{email_id.decode('utf-8')}.eml")
            with open(eml_filename, "wb") as eml_file:
                eml_file.write(raw_email)
            email_files.append(eml_filename)

        mail.logout()
        return email_files
    except Exception as e:
        print(f"Error fetching emails: {e}")
        return email_files

def get_email_content(eml_file):
    """
    Extract the content from an email file.
    
    Args:
        eml_file: Path to the email file
        
    Returns:
        Email message object
    """
    with open(eml_file, "rb") as file:
        return BytesParser(policy=default).parse(file)

def extract_email_text(msg):
    """
    Extract text content from an email message.
    
    Args:
        msg: Email message object
        
    Returns:
        Text content of the email
    """
    mail_data = ''
    if msg.is_multipart():
        parts = msg.get_payload()
        for part in parts:
            if part.get_content_type() == 'text/plain':
                mail_data += part.get_payload(decode=True).decode('utf-8', errors='replace')
            elif part.get_content_type() == 'text/html':
                mail_data += part.get_payload(decode=True).decode('utf-8', errors='replace')
    else:
        mail_data = msg.get_payload(decode=True).decode('utf-8', errors='replace')
    return mail_data

def extract_links(email_text):
    """
    Extract links from email text.
    
    Args:
        email_text: Email text content
        
    Returns:
        List of unique links
    """
    links = re.findall(LINK_REGEX, email_text)
    # Remove duplicates while preserving order
    return list(dict.fromkeys(links))
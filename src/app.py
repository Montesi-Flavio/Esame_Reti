import hashlib
import imaplib
import email
import os
import json
import re
from email import policy
from argparse import ArgumentParser
from datetime import datetime
from email.parser import BytesParser, HeaderParser

# Global Values
SUPPORTED_FILE_TYPES = ["eml"]
SUPPORTED_OUTPUT_TYPES = ["json", "html"]
LINK_REGEX = r'href=\"((?:\S)*)\"'
MAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
DATE_FORMAT = "%B %d, %Y - %H:%M:%S"
TER_COL_SIZE = 60
SERVER = "webmail.register.it"
USER = "test@maurimori.eu"
PASSWORD = "W2024pc!Q"

# Get EML Files
def get_eml_files(directory):
    '''Get EML Files from Directory'''
    eml_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".eml"):
                eml_files.append(os.path.join(root, file))
    return eml_files

# Get Headers
def get_headers(mail_data: str, investigation):
    '''Get Headers from mail data'''
    headers = HeaderParser().parsestr(mail_data, headersonly=True)
    data = json.loads('{"Headers":{"Data":{},"Investigation":{}}}')

    for k, v in headers.items():
        data["Headers"]["Data"][k.lower()] = v.replace('\t', '').replace('\n', '')

    if data["Headers"]["Data"].get('received'):
        data["Headers"]["Data"]["received"] = ' '.join(headers.get_all('Received')).replace('\t', '').replace('\n', '')
    
    if investigation:
        if data["Headers"]["Data"].get("x-sender-ip"):
            data["Headers"]["Investigation"]["X-Sender-Ip"] = {
                "Virustotal": f'https://www.virustotal.com/gui/search/{data["Headers"]["Data"]["x-sender-ip"]}',
                "Abuseipdb": f'https://www.abuseipdb.com/check/{data["Headers"]["Data"]["x-sender-ip"]}'
            }

        if data["Headers"]["Data"].get("reply-to") and data["Headers"]["Data"].get("from"):
            replyto = re.findall(MAIL_REGEX, data["Headers"]["Data"]["reply-to"])[0]
            mailfrom = re.findall(MAIL_REGEX, data["Headers"]["Data"]["from"])[0]

            if replyto == mailfrom:
                conclusion = "Reply Address and From Address is SAME."
            else:
                conclusion = "Reply Address and From Address is NOT Same. This mail may be SPOOFED." 

            data["Headers"]["Investigation"]["Spoof_check"] = {
                "Reply-To": replyto,
                "From": mailfrom,
                "Conclusion": conclusion
            }
    else:
        data["Headers"]["Investigation"].get("")
    return data

# Get Links
def get_links(mail_data : str, investigation):
    '''Get Links from mail data'''
    try:
        # Parse the email content
        msg = BytesParser(policy=policy.default).parsebytes(mail_data.encode('utf-8', errors='replace'))

        # Get the email body
        if msg.is_multipart():
            parts = msg.get_payload()
            mail_data = ''
            for part in parts:
                if part.get_content_type() == 'text/plain':
                    mail_data += part.get_payload(decode=True).decode('utf-8', errors='replace')
                elif part.get_content_type() == 'text/html':
                    mail_data += part.get_payload(decode=True).decode('utf-8', errors='replace')
        else:
            mail_data = msg.get_payload(decode=True).decode('utf-8', errors='replace')

        # Find the Links    
        links = re.findall(LINK_REGEX, mail_data)

        # Remove Duplicates and Empty Values
        links = list(filter(None, dict.fromkeys(links)))


        # Create JSON data
        data = json.loads('{"Links":{"Data":{},"Investigation":{}}}')

        for index,link in enumerate(links,start=1):
            data["Links"]["Data"][str(index)] = link
        
        # If investigation requested
        if investigation:
            for index,link in enumerate(links,start=1):
                # Remove http/s from link
                if "://" in link:
                    link = link.split("://")[-1]
                
                data["Links"]["Investigation"][str(index)] = {
                    "Virustotal":f"https://www.virustotal.com/gui/search/{link}",
                    "Urlscan":f"https://urlscan.io/search/#{link}"
                }
        return data
    except Exception as e:
        print(f"Error processing links: {e}")
        return json.loads('{"Links":{"Data":{},"Investigation":{}}}')


# Get Digests
def get_digests(mail_data : str, filename : str, investigation):
    '''Get Hash value of mail'''
    with open(filename, 'rb') as f:
        eml_file    = f.read()
        file_md5    = hashlib.md5(eml_file).hexdigest()
        file_sha1   = hashlib.sha1(eml_file).hexdigest()
        file_sha256 = hashlib.sha256(eml_file).hexdigest()

    content_md5     = hashlib.md5(mail_data.encode("utf-8")).hexdigest()
    content_sha1    = hashlib.sha1(mail_data.encode("utf-8")).hexdigest()
    content_sha256  = hashlib.sha256(mail_data.encode("utf-8")).hexdigest()

    # Create JSON data
    data = json.loads('{"Digests":{"Data":{},"Investigation":{}}}')

    # Write Data to JSON
    data["Digests"]["Data"]["File MD5"]         = file_md5
    data["Digests"]["Data"]["File SHA1"]        = file_sha1
    data["Digests"]["Data"]["File SHA256"]      = file_sha256
    data["Digests"]["Data"]["Content MD5"]      = content_md5
    data["Digests"]["Data"]["Content SHA1"]     = content_sha1
    data["Digests"]["Data"]["Content SHA256"]   = content_sha256

    # If investigation requested
    if investigation:
        data["Digests"]["Investigation"]["File MD5"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{file_md5}"
        }
        data["Digests"]["Investigation"]["File SHA1"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{file_sha1}"
        }
        data["Digests"]["Investigation"]["File SHA256"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{file_sha256}"
        }
        data["Digests"]["Investigation"]["Content MD5"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{content_md5}"
        }
        data["Digests"]["Investigation"]["Content SHA1"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{content_sha1}"
        }
        data["Digests"]["Investigation"]["Content SHA256"] = {
            "Virustotal":f"https://www.virustotal.com/gui/search/{content_sha256}"
        }
    return data

# Download Emails from IMAP Server
def download_emails(imap_server, email_user, email_pass, mailbox="Inbox", output_dir="emails"):
    '''Download emails from IMAP server and save as EML files'''

    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_user, email_pass)

    except Exception as e:
        print(f"Error: {e}")
        return

    mail.select(mailbox)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    result, data = mail.search(None, "ALL")
    email_ids = data[0].split()

    for email_id in email_ids:
        result, msg_data = mail.fetch(email_id, "(BODY.PEEK[])")
        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)
        eml_filename = os.path.join(output_dir, f"{email_id.decode('utf-8')}.eml")
        with open(eml_filename, "wb") as eml_file:
            eml_file.write(raw_email)

    mail.logout()

# Main Function chose the options
def main():
    parser = ArgumentParser(description="Email Analyzer")
    parser.add_argument("-s", "--server", type=str, help="IMAP server", required=True)
    parser.add_argument("-u", "--user", type=str, help="Email user", required=True)
    parser.add_argument("-p", "--password", type=str, help="Email password", required=True)
    parser.add_argument("-m", "--mailbox", type=str, help="Mailbox to download emails from", default="INBOX")
    parser.add_argument("-d", "--output-dir", type=str, help="Directory to save downloaded emails", default="emails")
    parser.add_argument("-h", "--headers", help="To get the Headers of the Email", required=False, action="store_true")
    parser.add_argument("-g", "--digests", help="To get the Digests of the Email", required=False, action="store_true")
    parser.add_argument("-l", "--links", help="To get the Links from the Email", required=False, action="store_true")
    parser.add_argument("-c", "--complete", help="Perform a complete analysis", required=False, action="store_true")
    parser.add_argument("-a", "--attachments", help="To get the Attachments from the Email", required=False, action="store_true")
    parser.add_argument("-i", "--investigate", help="Activate if you want an investigation", required=False, action="store_true")
    parser.add_argument("-o", "--output", type=str, help="Name of the Output file (Only HTML or JSON format supported)", required=False)
    args = parser.parse_args()

    download_emails(SERVER, USER, PASSWORD, args.mailbox, args.output_dir)
    eml_files = get_eml_files(args.output_dir)
    all_data = []

    for filename in eml_files:
        with open(filename, "r", encoding="utf-8") as file:
            data = file.read().rstrip()

        app_data = json.loads('{"Information": {}, "Analysis":{}}')
        
        app_data["Information"]["Scan"] = {
            "Filename": filename,
            "Generated": str(datetime.now().strftime(DATE_FORMAT))
        }
        
        if args.headers or args.complete:
            headers = get_headers(data, args.investigate)
            app_data["Analysis"].update(headers)

        if args.digests or args.complete:
            digests = get_digests(data, filename, args.investigate)
            app_data["Analysis"].update(digests)

        if args.links or args.complete:
            links = get_links(data, args.investigate)
            app_data["Analysis"].update(links)
        
        all_data.append(app_data)

    output_filename = args.output if args.output else "outputfile.json"
    with open(output_filename, 'w', encoding='utf-8') as f:
        json.dump(all_data, f, ensure_ascii=False, indent=4)
    print(f"Your data has been written to the {output_filename}")

if __name__ == '__main__':
    main()
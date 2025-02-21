from email.policy import default
import hashlib
import imaplib
import os
import json
import re
import dns.exception
import dns.resolver
import vt

from email.parser import BytesParser, HeaderParser
from argparse import ArgumentParser

# Global Values
VIRUSTOTAL_API_KEY = "bd967895e71ce6eeb87d62f473b94fcc29e2afddf79d4d40b821e003ceef9b15"
SUPPORTED_FILE_TYPES = ["eml"]
SUPPORTED_OUTPUT_TYPES = ["json", "html"]
LINK_REGEX = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
MAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
DATE_FORMAT = "%B %d, %Y - %H:%M:%S"
BLACKLISTS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]

SERVER = "webmail.register.it"
USER = "test@maurimori.eu"
PASSWORD = "W2024pc!Q"

# Utility Functions
def safe_resolve(query, record_type):
    try:
        return dns.resolver.resolve(query, record_type)
    except dns.exception.DNSException:
        return None

def check_ip_safety(ip):
    '''Check if an IP is safe using VirusTotal'''
    client = vt.Client(VIRUSTOTAL_API_KEY)
    try:
        analysis = client.get_object(f"/ip_addresses/{ip}")
        positives = analysis.last_analysis_stats['malicious']
        if positives > 0:
            return False, positives
        else:
            return True, 0
    except vt.error.APIError as e:
        print(f"Error making request to VirusTotal: {e}")
        return None, None
    finally:
        client.close()

def fetch_emails(imap_server, email_user, email_pass, mailbox="INBOX", output_dir="emails"):
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_user, email_pass)
        mail.select(mailbox)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        result, data = mail.search(None, "ALL")
        if result != "OK":
            print("Error fetching emails.")
            return

        email_ids = data[0].split()
        for email_id in email_ids:
            result, msg_data = mail.fetch(email_id, "(BODY.PEEK[])")
            if result != "OK":
                continue
            raw_email = msg_data[0][1]
            eml_filename = os.path.join(output_dir, f"{email_id.decode('utf-8')}.eml")
            with open(eml_filename, "wb") as eml_file:
                eml_file.write(raw_email)

        mail.logout()
    except Exception as e:
        print(f"Error fetching emails: {e}")

def parse_email_headers(mail_data, investigation):
    headers = HeaderParser().parsestr(mail_data, headersonly=True)
    parsed_headers = {"Data": {}, "Investigation": {}}

    for k, v in headers.items():
        parsed_headers["Data"][k.lower()] = v.replace('\t', '').replace('\n', '')

    if 'received' in parsed_headers["Data"]:
        parsed_headers["Data"]['received'] = ' '.join(headers.get_all('Received', [])).replace('\t', '').replace('\n', '')

    if investigation:
        # Estrarre IP dai campi "Received"
        received_headers = headers.get_all('Received')
        if received_headers:
            last_received = received_headers[-1]
            sender_ip_match = re.search(r'\[([0-9.]+)\]', last_received)
            if sender_ip_match:
                sender_ip = sender_ip_match.group(1)
            else:
                sender_ip = None
        else:
            sender_ip = None

        if sender_ip:
            # Verifica IP su VirusTotal
            safe, positives = check_ip_safety(sender_ip)
            safety_status = "Safe" if safe else "Unsafe"
            parsed_headers["Investigation"]["X-Sender-Ip"] = {
                "Virustotal": f"https://www.virustotal.com/gui/search/{sender_ip}",
                "Abuseipdb": f"https://www.abuseipdb.com/check/{sender_ip}",
                "Safety": safety_status,
                "Positives": positives
            }

            # Verifica IP nei Blacklist
            blacklisted, blacklist = check_blacklist(sender_ip)
            if blacklisted:
                parsed_headers["Investigation"]["Blacklist_Check"] = {
                    "Blacklist_Status": "Blacklisted",
                    "Blacklist": blacklist
                }
            else:
                parsed_headers["Investigation"]["Blacklist_Check"] = {
                    "Blacklist_Status": "Not Blacklisted"
                }

    return {"Headers": parsed_headers}

def check_blacklist(ip):
    for blacklist in BLACKLISTS:
        query = f"{'.'.join(reversed(ip.split('.')))}.{blacklist}"
        if safe_resolve(query, 'A'):
            return True, blacklist
    return False, None

def check_dmarc(domain):
    dmarc_record = safe_resolve(f'_dmarc.{domain}', 'TXT')
    if dmarc_record:
        for txt_record in dmarc_record:
            if 'v=DMARC1' in txt_record.to_text():
                return True, txt_record.to_text()
    return False, None

def analyze_links(mail_data, investigation):
    ''' Extract links and optionally investigate their safety '''

    # Parse the email content
    msg = BytesParser(policy=default).parsebytes(mail_data.encode('utf-8', errors='replace'))

    # Get the email body
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

    # Find all links in the email body using the LINK_REGEX
    links = re.findall(LINK_REGEX, mail_data)

    # Remove duplicates and empty values
    links = list(filter(None, dict.fromkeys(links)))

    link_data = {}
    for index, link in enumerate(links, start=1):
        link_data[str(index)] = link

    investigation_data = {}
    if investigation:
        client = vt.Client(VIRUSTOTAL_API_KEY)
        for index, link in enumerate(links, start=1):
            try:
                analysis = client.get_object(f"/urls/{vt.url_id(link)}")
                if hasattr(analysis, 'last_analysis_stats'):
                    positives = analysis.last_analysis_stats.get('malicious', 0)
                    investigation_data[str(index)] = {
                        "Virustotal": f"https://www.virustotal.com/gui/search/{link}",
                        "Safety": "Safe" if positives == 0 else "Unsafe",
                        "Positives": positives
                    }
                else:
                    investigation_data[str(index)] = {
                        "Error": "No analysis data available"
                    }
            except vt.error.APIError:
                investigation_data[str(index)] = {
                    "Error": "Unable to fetch data from VirusTotal"
                }
        client.close()

    return {"Links": {"Data": link_data, "Investigation": investigation_data}}

def calculate_hashes(filename, investigation):
    with open(filename, 'rb') as f:
        file_data = f.read()
    hashes = {
        "File MD5": hashlib.md5(file_data).hexdigest(),
        "File SHA1": hashlib.sha1(file_data).hexdigest(),
        "File SHA256": hashlib.sha256(file_data).hexdigest()
    }

    investigation_data = {}
    if investigation:
        client = vt.Client(VIRUSTOTAL_API_KEY)
        for hash_type, hash_value in hashes.items():
            try:
                analysis = client.get_object(f"/files/{hash_value}")
                positives = analysis.last_analysis_stats.get('malicious', 0)
                investigation_data[hash_type] = {
                    "Virustotal": f"https://www.virustotal.com/gui/file/{hash_value}",
                    "Safety": "Safe" if positives == 0 else "Unsafe",
                    "Positives": positives
                }
            except vt.error.APIError:
                investigation_data[hash_type] = {
                    "Error": "Unable to fetch data from VirusTotal"
                }
        client.close()
    return {"Hashes": {"Data": hashes, "Investigation": {}}}

def main():
    parser = ArgumentParser(description="Email Analyzer")
    parser.add_argument("-s", "--server", required=False, help="IMAP server")
    parser.add_argument("-u", "--user", required=False, help="Email user")
    parser.add_argument("-p", "--password", required=False, help="Email password")
    parser.add_argument("-m", "--mailbox", default="INBOX", help="Mailbox to download emails from")
    parser.add_argument("-d", "--output-dir", default="emails", help="Directory to save downloaded emails")
    parser.add_argument("-i", "--investigate", action="store_true", help="Enable investigation mode")
    parser.add_argument("-o", "--output", required=False, help="Output file name (JSON or HTML)")

    args = parser.parse_args()

    if args.output and not any(args.output.endswith(ext) for ext in SUPPORTED_OUTPUT_TYPES):
        print("Error: Output file must be in JSON or HTML format.")
        return

    fetch_emails(SERVER, USER, PASSWORD, args.mailbox, args.output_dir)

    eml_files = [os.path.join(args.output_dir, f) for f in os.listdir(args.output_dir) if f.endswith(".eml")]
    all_data = []

    for eml_file in eml_files:
        with open(eml_file, "rb") as file:
            mail_data = BytesParser(policy=default).parse(file)
        
        headers = parse_email_headers(mail_data.as_string(), args.investigate)
        hashes = calculate_hashes(eml_file, args.investigate)        
        links_data = analyze_links(mail_data.as_string(), args.investigate)

        all_data.append({
            "File": eml_file,
            "Headers": headers,
            "Hashes": hashes,
            "Links": links_data
        })

    output_filename = args.output if args.output else "outputfile.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(all_data, f,ensure_ascii=False, indent=4)

    print(f"Analysis complete. Results saved to {output_filename}")

if __name__ == "__main__":
    main()

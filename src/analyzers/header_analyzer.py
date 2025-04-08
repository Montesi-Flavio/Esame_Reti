"""
Header analysis functionality for email investigation.
"""

import re
from email.parser import HeaderParser
from connectors import check_ip_safety, check_blacklist

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

            # Check IP against blacklists
            blacklist_results = check_ip_blacklists(sender_ip)
            if blacklist_results:
                parsed_headers["Investigation"]["Blacklist_Check"] = blacklist_results

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
    safe, positives = check_ip_safety(ip)
    if safe is None:
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
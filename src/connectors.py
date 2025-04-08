"""
Connectors for external services like VirusTotal and DNS lookups.
"""

import dns.exception
import dns.resolver
import vt
from config import VIRUSTOTAL_API_KEY, BLACKLISTS

def safe_resolve(query, record_type):
    """
    Safely resolve DNS queries and handle exceptions.
    
    Args:
        query: The DNS query to resolve
        record_type: The DNS record type to query
        
    Returns:
        DNS resolver result or None if resolution fails
    """
    try:
        return dns.resolver.resolve(query, record_type)
    except dns.exception.DNSException:
        return None

def check_ip_safety(ip):
    """
    Check if an IP is safe using VirusTotal.
    
    Args:
        ip: The IP address to check
        
    Returns:
        Tuple (is_safe, positives) where is_safe is a boolean and positives is the number
        of malicious detections or None if the check fails
    """
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

def check_blacklist(ip):
    """
    Check if an IP is in any blacklist.
    
    Args:
        ip: The IP address to check
        
    Returns:
        Tuple (blacklisted, blacklist) where blacklisted is a boolean and blacklist
        is the name of the blacklist or None if not blacklisted
    """
    for blacklist in BLACKLISTS:
        query = f"{'.'.join(reversed(ip.split('.')))}.{blacklist}"
        if safe_resolve(query, 'A'):
            return True, blacklist
    return False, None

def check_url_safety(url):
    """
    Check if a URL is safe using VirusTotal.
    
    Args:
        url: The URL to check
        
    Returns:
        Tuple (is_safe, positives, error) where is_safe is a boolean,
        positives is the number of malicious detections, and error is an error message or None
    """
    client = vt.Client(VIRUSTOTAL_API_KEY)
    try:
        analysis = client.get_object(f"/urls/{vt.url_id(url)}")
        if hasattr(analysis, 'last_analysis_stats'):
            positives = analysis.last_analysis_stats.get('malicious', 0)
            return (positives == 0), positives, None
        else:
            return None, None, "No analysis data available"
    except vt.error.APIError as e:
        return None, None, f"Error making request to VirusTotal: {e}"
    finally:
        client.close()

def check_hash_safety(hash_value):
    """
    Check if a file hash is safe using VirusTotal.
    
    Args:
        hash_value: The hash value to check
        
    Returns:
        Tuple (is_safe, positives, error) where is_safe is a boolean,
        positives is the number of malicious detections, and error is an error message or None
    """
    client = vt.Client(VIRUSTOTAL_API_KEY)
    try:
        analysis = client.get_object(f"/files/{hash_value}")
        positives = analysis.last_analysis_stats.get('malicious', 0)
        return (positives == 0), positives, None
    except vt.error.APIError as e:
        return None, None, f"Error making request to VirusTotal: {e}"
    finally:
        client.close()

def check_dmarc(domain):
    """
    Check if a domain has DMARC records.
    
    Args:
        domain: The domain to check
        
    Returns:
        Tuple (has_dmarc, record) where has_dmarc is a boolean and record is
        the DMARC record or None if no DMARC record exists
    """
    dmarc_record = safe_resolve(f'_dmarc.{domain}', 'TXT')
    if dmarc_record:
        for txt_record in dmarc_record:
            if 'v=DMARC1' in txt_record.to_text():
                return True, txt_record.to_text()
    return False, None
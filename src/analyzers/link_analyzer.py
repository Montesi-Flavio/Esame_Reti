"""
Link analysis functionality for email investigation.
"""

import re
from config import LINK_REGEX
from connectors import check_url_safety

def analyze_links(mail_data, investigation=False):
    """
    Extract links from email and optionally investigate their safety.
    
    Args:
        mail_data: Email content as string
        investigation: Whether to perform security investigation
        
    Returns:
        Dictionary with links data and investigation results
    """
    # Find all links in the email body
    links = re.findall(LINK_REGEX, mail_data)

    # Remove duplicates and empty values
    links = list(filter(None, dict.fromkeys(links)))

    # Format links as a dictionary
    link_data = {}
    for index, link in enumerate(links, start=1):
        link_data[str(index)] = link

    # Perform safety investigation if requested
    investigation_data = {}
    if investigation and links:
        for index, link in enumerate(links, start=1):
            safe, positives, error = check_url_safety(link)
            
            if error:
                investigation_data[str(index)] = {
                    "Error": error
                }
            else:
                investigation_data[str(index)] = {
                    "Virustotal": f"https://www.virustotal.com/gui/search/{link}",
                    "Safety": "Safe" if safe else "Unsafe",
                    "Positives": positives
                }

    return {"Data": link_data, "Investigation": investigation_data}
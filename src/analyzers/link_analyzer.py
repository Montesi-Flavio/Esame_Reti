"""
Link analysis functionality for email investigation.
"""

import re
from email import message_from_string
from email.parser import Parser
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from config import LINK_REGEX
from connectors import check_url_safety

class LinkExtractor(HTMLParser):
    """HTML parser to extract links from HTML content."""
    def __init__(self):
        super().__init__()
        self.links = set()
        
    def handle_starttag(self, tag, attrs):
        # Extract links from href and src attributes
        attrs = dict(attrs)
        if tag in ['a', 'link'] and 'href' in attrs:
            self.links.add(attrs['href'])
        elif tag in ['img', 'script'] and 'src' in attrs:
            self.links.add(attrs['src'])

def is_valid_url(url):
    """Check if a URL is valid."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def extract_text_links(text):
    """Extract links from plain text using regex."""
    if not text:
        return set()
    links = set()
    # Updated regex to catch more URL formats
    url_pattern = r'(?:https?:\/\/)?(?:[\w-]+\.)+[\w-]+(?:\/[^\s<>"]*)?'
    matches = re.finditer(url_pattern, text, re.IGNORECASE)
    for match in matches:
        url = match.group(0)
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        if is_valid_url(url):
            links.add(url)
    return links

def analyze_links(mail_data, investigation=False):
    """
    Extract links from email and optionally investigate their safety.
    
    Args:
        mail_data: Email content as string
        investigation: Whether to perform security investigation
        
    Returns:
        Dictionary with links data and investigation results
    """
    links = set()
    
    # Parse email content
    if isinstance(mail_data, str):
        msg = message_from_string(mail_data)
    else:
        msg = mail_data
        
    # Extract links from HTML parts
    html_parser = LinkExtractor()
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == 'text/html':
            try:
                html_content = part.get_payload(decode=True).decode()
                html_parser.feed(html_content)
                links.update(html_parser.links)
            except:
                pass
        elif content_type == 'text/plain':
            try:
                text_content = part.get_payload(decode=True).decode()
                text_links = extract_text_links(text_content)
                links.update(text_links)
            except:
                pass

    # Process and clean the links
    cleaned_links = []
    for link in links:
        try:
            # Handle relative URLs and normalize
            if not link.startswith(('http://', 'https://')):
                continue
            # Clean and validate the URL
            if is_valid_url(link):
                cleaned_links.append(link)
        except:
            continue

    # Remove duplicates and sort
    cleaned_links = sorted(set(cleaned_links))
    
    # Base result structure
    result = {
        "total_links": len(cleaned_links),
        "unique_links": [],
        "investigation_results": [] if investigation else None
    }

    # Investigate links if requested
    if investigation:
        for link in cleaned_links:
            is_safe, detections, error = check_url_safety(link)
            link_data = {
                "url": link,
                "safety_score": 100 if is_safe else (0 if is_safe is not None else 50),
                "threats": [f"{detections} malicious detections"] if detections else [],
                "error": error if error else None,
                "domain": urlparse(link).netloc,
                "scheme": urlparse(link).scheme
            }
            result["unique_links"].append(link_data)
            result["investigation_results"].append(link_data)
    else:
        # Just add basic URL info without investigation
        for link in cleaned_links:
            parsed = urlparse(link)
            link_data = {
                "url": link,
                "domain": parsed.netloc,
                "scheme": parsed.scheme
            }
            result["unique_links"].append(link_data)

    return result
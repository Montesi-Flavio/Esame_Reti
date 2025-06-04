"""
Link analysis functionality for email investigation.
"""

import re
import time
import logging
from email import message_from_string
from email.parser import Parser
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from config import LINK_REGEX
from connectors import check_url_safety

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('link_analyzer')

class LinkExtractor(HTMLParser):
    """HTML parser to extract links from HTML content."""
    def __init__(self):
        super().__init__()
        self.links = set()
        
    def handle_starttag(self, tag, attrs):
        # Extract links from href and src attributes
        attrs = dict(attrs)
        if tag in ['a', 'link'] and 'href' in attrs:
            if attrs['href'] and not attrs['href'].startswith('mailto:'):
                self.links.add(attrs['href'])
        elif tag in ['img', 'script'] and 'src' in attrs:
            if attrs['src']:
                self.links.add(attrs['src'])
                
    def reset(self):
        """Reset the parser and clear the links."""
        super().reset()
        self.links = set()

def is_valid_url(url):
    """Check if a URL is valid."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception as e:
        logger.debug(f"Error validating URL {url}: {e}")
        return False

def normalize_url(url):
    """Normalize URL by adding scheme if missing and ensuring valid format."""
    try:
        if not url:
            return None
            
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Parse and rebuild to normalize
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return None
            
        # Remove fragments as they don't change the resource
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
            
        return normalized
    except Exception as e:
        logger.debug(f"Error normalizing URL {url}: {e}")
        return None

def extract_text_links(text):
    """Extract links from plain text using regex."""
    if not text:
        return set()
    links = set()
    # Improved regex to catch more URL formats while reducing false positives
    url_pattern = r'(?:https?:\/\/)?(?:www\.)?(?:[\w-]+\.)+[a-zA-Z]{2,}(?:\/[^\s<>"\']*)?'
    matches = re.finditer(url_pattern, text, re.IGNORECASE)
    for match in matches:
        url = match.group(0)
        normalized_url = normalize_url(url)
        if normalized_url:
            links.add(normalized_url)
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
    
    start_time = time.time()
    logger.info("Starting link extraction...")
    
    # Extract links from HTML parts
    html_parser = LinkExtractor()
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == 'text/html':
            try:
                html_content = part.get_payload(decode=True).decode('utf-8', errors='replace')
                html_parser.feed(html_content)
                links.update(html_parser.links)
                # Reset parser for next HTML part to avoid memory issues
                html_parser.reset()
            except Exception as e:
                logger.debug(f"Error parsing HTML content: {e}")
        elif content_type == 'text/plain':
            try:
                text_content = part.get_payload(decode=True).decode('utf-8', errors='replace')
                text_links = extract_text_links(text_content)
                links.update(text_links)
            except Exception as e:
                logger.debug(f"Error parsing plain text content: {e}")

    # Process and clean the links
    cleaned_links = []
    unique_normalized_urls = set()
    
    for link in links:
        try:
            # Normalize the URL to avoid duplicates with slight differences
            normalized_url = normalize_url(link)
            if normalized_url and normalized_url not in unique_normalized_urls:
                unique_normalized_urls.add(normalized_url)
                cleaned_links.append(normalized_url)
        except Exception as e:
            logger.debug(f"Error processing link {link}: {e}")
            
    logger.info(f"Link extraction completed in {time.time() - start_time:.2f}s. Found {len(cleaned_links)} unique links.")

    # Sort for consistent output
    cleaned_links = sorted(cleaned_links)
    
    # Base result structure
    result = {
        "total_links": len(cleaned_links),
        "unique_links": [],
        "investigation_results": [] if investigation else None
    }

    # Batch processing for better performance
    batch_size = 5  # Process links in small batches to avoid overloading
    
    # Helper function to create link data object
    def create_link_data(link, safety_info=None):
        parsed = urlparse(link)
        link_data = {
            "url": link,
            "domain": parsed.netloc,
            "scheme": parsed.scheme
        }
        
        if safety_info:
            is_safe, detections, error = safety_info
            link_data.update({
                "safety_score": 100 if is_safe else (0 if is_safe is not None else 50),
                "threats": [f"{detections} malicious detections"] if detections else [],
                "error": error if error else None
            })
            
        return link_data

    # Investigate links if requested
    if investigation and cleaned_links:
        logger.info(f"Starting safety investigation for {len(cleaned_links)} links...")
        start_time = time.time()
        
        # Process links in batches to avoid rate limit issues
        for i in range(0, len(cleaned_links), batch_size):
            batch = cleaned_links[i:i+batch_size]
            
            for link in batch:
                try:
                    # Add delay between batches to respect API limits
                    if i > 0 and i % batch_size == 0:
                        time.sleep(1)
                        
                    is_safe, detections, error = check_url_safety(link)
                    link_data = create_link_data(link, (is_safe, detections, error))
                    
                    result["unique_links"].append(link_data)
                    result["investigation_results"].append(link_data)
                    
                    if error and "QuotaExceeded" in error:
                        logger.warning(f"VirusTotal API quota exceeded. Processing remaining links without investigation.")
                        # Process remaining links without investigation
                        for remaining_link in cleaned_links[i+batch.index(link)+1:]:
                            basic_link_data = create_link_data(remaining_link)
                            result["unique_links"].append(basic_link_data)
                        
                        # Set investigation_results to reflect the error
                        result["error"] = "VirusTotal API quota exceeded. Not all links were investigated."
                        return result
                        
                except Exception as e:
                    logger.error(f"Error investigating link {link}: {e}")
                    # Add basic info for this link if investigation fails
                    result["unique_links"].append(create_link_data(link))
        
        logger.info(f"Link investigation completed in {time.time() - start_time:.2f}s")
    else:
        # Just add basic URL info without investigation
        for link in cleaned_links:
            result["unique_links"].append(create_link_data(link))

    return result
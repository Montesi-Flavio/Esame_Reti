"""
Link analysis functionality for email investigation.

This module provides functions to extract and analyze links from email content,
with optional security investigation using VirusTotal API. It includes:
- HTML and plain text link extraction
- URL normalization and validation
- Security analysis with VirusTotal (with caching)
- Handling of API rate limits and quota exceedance
"""

import re
import time
import logging
from email import message_from_string
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
import hashlib
from config import LINK_REGEX
from connectors import check_url_safety

# Configure logging with a more specific name for better filtering
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('email_analyzer.link_analyzer')

class LinkExtractor(HTMLParser):
    """HTML parser to extract links from HTML content.
    
    Extracts URLs from various HTML elements including:
    - href attributes (a, link, area tags)
    - src attributes (img, script, iframe, video, audio, source tags)
    - data-* attributes (custom data attributes that might contain URLs)
    - background attributes (older HTML elements)
    - meta refresh redirects
    
    Filters out non-web protocols like mailto:, tel:, javascript:
    """
    def __init__(self):
        super().__init__()
        self.links = set()
        
    def handle_starttag(self, tag, attrs):
        """Process HTML start tags to extract URLs.
        
        Args:
            tag: The HTML tag name
            attrs: List of attribute tuples (name, value)
        """
        attrs_dict = dict(attrs)
        
        # Process href attributes (navigation and link elements)
        if tag in ['a', 'link', 'area'] and 'href' in attrs_dict:
            href = attrs_dict['href']
            if href and not href.startswith(('mailto:', 'tel:', 'javascript:', 'data:')):
                self.links.add(href)
                
        # Process src attributes (embedded content)
        elif tag in ['img', 'script', 'iframe', 'video', 'audio', 'source', 'embed'] and 'src' in attrs_dict:
            src = attrs_dict['src']
            if src and not src.startswith(('data:', 'javascript:')):
                self.links.add(src)
        
        # Process background attributes (older HTML)
        elif 'background' in attrs_dict:
            background = attrs_dict['background']
            if background:
                self.links.add(background)
                
        # Process meta refresh redirects
        elif tag == 'meta' and attrs_dict.get('http-equiv', '').lower() == 'refresh':
            content = attrs_dict.get('content', '')
            if content:
                # Extract URL from content="0;URL=http://example.com/"
                parts = content.split(';', 1)
                if len(parts) > 1:
                    url_part = parts[1].strip()
                    if url_part.lower().startswith('url='):
                        url = url_part[4:].strip()
                        if url:
                            self.links.add(url)
        
        # Process data-* attributes that might contain URLs
        for attr_name, attr_value in attrs:
            if attr_name.startswith('data-') and attr_value and (
                    attr_value.startswith('http') or 
                    attr_value.startswith('www.') or 
                    attr_value.startswith('//')):
                self.links.add(attr_value)
                
    def reset(self):
        """Reset the parser and clear the links collection."""
        super().reset()
        self.links = set()

def is_valid_url(url):
    """Check if a URL is valid by ensuring it has both scheme and network location.
    
    Args:
        url: URL string to validate
        
    Returns:
        Boolean indicating if the URL is valid
    """
    try:
        if not url or not isinstance(url, str):
            return False
            
        result = urlparse(url)
        # A valid URL must have both a scheme (http, https) and a network location (domain)
        return all([result.scheme, result.netloc])
    except Exception as e:
        logger.debug(f"Error validating URL {url}: {e}")
        return False

def normalize_url(url):
    """Normalize URL by adding scheme if missing and standardizing format.
    
    This function:
    - Adds 'http://' scheme if missing
    - Validates the URL structure
    - Removes fragments (#) as they don't change the resource content
    - Preserves query parameters
    
    Args:
        url: URL string to normalize
        
    Returns:
        Normalized URL string or None if URL is invalid
    """
    try:
        if not url or not isinstance(url, str):
            return None
            
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Parse and rebuild to normalize
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return None
            
        # Rebuild URL without fragments
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if parsed.query:
            normalized += f"?{parsed.query}"
            
        return normalized
    except Exception as e:
        logger.debug(f"Error normalizing URL {url}: {e}")
        return None

def extract_text_links(text):
    """Extract URLs from plain text content using regular expressions.
    
    Args:
        text: Plain text content to search for URLs
        
    Returns:
        Set of normalized URLs found in the text
    """
    if not text or not isinstance(text, str):
        return set()
        
    links = set()
    
    # Regex pattern for URL detection with improved accuracy:
    # - Optional http/https prefix
    # - Optional www prefix
    # - Domain with at least one dot and valid TLD
    # - Optional path, parameters, etc.
    url_pattern = r'(?:https?:\/\/)?(?:www\.)?(?:[\w-]+\.)+[a-zA-Z]{2,}(?:\/[^\s<>"\']*)?'
    
    try:
        matches = re.finditer(url_pattern, text, re.IGNORECASE)
        for match in matches:
            url = match.group(0)
            normalized_url = normalize_url(url)
            if normalized_url:
                links.add(normalized_url)
    except Exception as e:
        logger.error(f"Error extracting text links: {e}")
    
    return links

def analyze_links(mail_data, investigation=False):
    """
    Extract links from email content and optionally investigate their safety.
    
    This function:
    1. Parses the email content
    2. Extracts links from both HTML and plain text parts
    3. Normalizes and deduplicates the links
    4. Optionally investigates link safety using VirusTotal
    
    Args:
        mail_data: Email content as string or email.message object
        investigation: Whether to perform security investigation
        
    Returns:
        Dictionary with links data and investigation results
    """
    links = set()
    
    # Parse email content if needed
    if isinstance(mail_data, str):
        msg = message_from_string(mail_data)
    else:
        msg = mail_data
    
    start_time = time.time()
    logger.info("Starting link extraction...")
    
    # Extract links from email parts
    html_parser = LinkExtractor()
    
    # Iterate through all email parts
    for part in msg.walk():
        content_type = part.get_content_type()
        
        # Process HTML parts
        if content_type == 'text/html':
            try:
                # Get and decode content
                html_content = part.get_payload(decode=True)
                if html_content:
                    html_content = html_content.decode('utf-8', errors='replace')
                    
                    # Feed content to HTML parser
                    html_parser.feed(html_content)
                    links.update(html_parser.links)
                    
                    # Reset parser for next HTML part
                    html_parser.reset()
            except Exception as e:
                logger.debug(f"Error parsing HTML content: {e}")
                
        # Process plain text parts
        elif content_type == 'text/plain':
            try:
                # Get and decode content
                text_content = part.get_payload(decode=True)
                if text_content:
                    text_content = text_content.decode('utf-8', errors='replace')
                    
                    # Extract links using regex
                    text_links = extract_text_links(text_content)
                    links.update(text_links)
            except Exception as e:
                logger.debug(f"Error parsing plain text content: {e}")    # Process, normalize and deduplicate links
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
    
    # Sort alphabetically for consistent output
    cleaned_links = sorted(cleaned_links)
    
    extraction_time = time.time() - start_time
    logger.info(f"Link extraction completed in {extraction_time:.2f}s. Found {len(cleaned_links)} unique links.")
    
    # Prepare result dictionary structure
    result = {
        "total_links": len(cleaned_links),
        "unique_links": [],
        "investigation_results": [] if investigation else None
    }

    # Batch processing for better performance
    batch_size = 5  # Process links in small batches to avoid overloading
    
    # Helper function to create link data object
    def create_link_data(link, safety_info=None):
        """Create a structured data object for a URL.
        
        Args:
            link: URL string
            safety_info: Optional tuple of (is_safe, detections, error) from security checks
            
        Returns:
            Dictionary with URL information and optional security data
        """
        parsed = urlparse(link)
        link_data = {
            "url": link,
            "domain": parsed.netloc,
            "scheme": parsed.scheme
        }
        
        if safety_info:
            is_safe, detections, error = safety_info
            
            # Calculate safety score: 100 for safe, 0 for unsafe, 50 for unknown
            safety_score = 100 if is_safe else (0 if is_safe is not None else 50)
            
            # Add security information to the link data
            link_data.update({
                "safety_score": safety_score,
                "threats": [f"{detections} malicious detections"] if detections else [],
                "error": error if error else None
            })
            
        return link_data    # Perform security investigation if requested
    if investigation and cleaned_links:
        logger.info(f"Starting safety investigation for {len(cleaned_links)} links...")
        investigation_start_time = time.time()
        
        # Process links in batches to avoid rate limit issues
        for i in range(0, len(cleaned_links), batch_size):
            batch = cleaned_links[i:i+batch_size]
            
            # Process each link in the current batch
            for link in batch:
                try:
                    # Add delay between batches to respect API limits
                    if i > 0 and i % batch_size == 0:
                        time.sleep(1)
                    
                    # Check link safety with VirusTotal
                    is_safe, detections, error = check_url_safety(link)
                    
                    # Create structured data with safety information
                    link_data = create_link_data(link, (is_safe, detections, error))
                    
                    # Add to results
                    result["unique_links"].append(link_data)
                    result["investigation_results"].append(link_data)
                    
                    # Handle quota exceeded error
                    if error and "QuotaExceeded" in error:
                        logger.warning("VirusTotal API quota exceeded. Processing remaining links without investigation.")
                        
                        # Process remaining links without security check
                        remaining_links = cleaned_links[i+batch.index(link)+1:]
                        for remaining_link in remaining_links:
                            basic_link_data = create_link_data(remaining_link)
                            result["unique_links"].append(basic_link_data)
                        
                        # Add error information to the result
                        result["error"] = "VirusTotal API quota exceeded. Not all links were investigated."
                        return result
                        
                except Exception as e:
                    logger.error(f"Error investigating link {link}: {e}")
                    # Add basic info for this link if investigation fails
                    result["unique_links"].append(create_link_data(link))
        
        investigation_time = time.time() - investigation_start_time
        logger.info(f"Link investigation completed in {investigation_time:.2f}s")
    else:
        # No investigation requested, just add basic URL info
        for link in cleaned_links:
            result["unique_links"].append(create_link_data(link))

    return result
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
from connectors import check_url_safety, comprehensive_url_analysis

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

def is_url_shortener(url):
    """Check if the URL is from a known URL shortener service.
    
    Args:
        url: The URL to check
        
    Returns:
        Boolean indicating if the URL is from a shortener service
    """
    shorteners = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 
        'adf.ly', 'tiny.cc', 'tr.im', 'x.co', 'cli.gs', 'u.to', 'qr.net', 'j.mp',
        'rebrand.ly', 'snip.ly', 'bl.ink', 'shor.by', 'tiny.pl', 'clicky.me',
        's2r.co', 'v.gd', 'shorturl.at', 'clickme.to', 'go2l.ink', 'surl.li',
        'qr.ae', 'rb.gy', 'su.pr', 'dlvr.it', 'urlz.fr', 'shorturl', 'snipurl',
        'filoops.info', 'migre.me', 'short.ie', 'shrinkster', 'vurl.bz',
        'href.li', 'cutt.ly', 'yourls.org', 'plu.sh', 'zws.im', 'shrunken.com', 
        'mcaf.ee'  # McAfee shortener, often used in phishing
    ]
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # Controlla sia il dominio esatto che i sottodomini
    return any(domain == shortener or domain.endswith('.' + shortener) for shortener in shorteners)

def create_link_data(link, safety_info=None, comprehensive_results=None):
    """Create a structured data object for a URL.
    
    Args:
        link: URL string
        safety_info: Optional tuple of (is_safe, detections, error) from single security checks
        comprehensive_results: Optional results from comprehensive_url_analysis
        
    Returns:
        Dictionary with URL information and optional security data
    """
    parsed = urlparse(link)
    link_data = {
        "url": link,
        "domain": parsed.netloc,
        "scheme": parsed.scheme
    }
    
    # Check if the URL is from a shortener service
    is_shortener = is_url_shortener(link)
    if is_shortener:
        link_data["shortener"] = True
    
    # Handle comprehensive security analysis results
    if comprehensive_results:
        # Get risk score and recommendation from comprehensive results
        risk_score = comprehensive_results.get('risk_score', 5)
        recommendation = comprehensive_results.get('recommendation', 'Unknown')
        
        # Convert risk_score (0-10) to threat_score (0-100)
        threat_score = risk_score * 10
        
        # Apply stricter risk level determination
        risk_level = "Unknown"
        
        # Per URL shortener, utilizziamo una logica più aggressiva
        if is_shortener:
            if threat_score > 0:
                # Qualsiasi threat score per uno shortener è considerato almeno medio rischio
                risk_level = "Medium Risk"
                if threat_score >= 20:
                    risk_level = "High Risk"
            else:
                # Anche se non ci sono minacce, gli shortener sono comunque "Low Risk"
                risk_level = "Low Risk"
        else:
            # Logica normale ma più severa per gli URL standard
            if "SAFE" in recommendation and threat_score == 0:
                risk_level = "Safe"
            elif threat_score <= 10:
                risk_level = "Low Risk"
            elif threat_score <= 30:
                risk_level = "Medium Risk"
            else:
                risk_level = "High Risk"
                
        # Override espliciti basati sulla raccomandazione
        if "BLOCK" in recommendation or "QUARANTINE" in recommendation:
            risk_level = "High Risk"
        
        # Extract recommendations from the comprehensive results
        recommendations = []
        if recommendation and ("SAFE" not in recommendation):
            recommendations.append(recommendation)
            
        # Add URL shortener warning
        if is_shortener:
            recommendations.append("URL shortener detected - consider analyzing the full destination URL")
        
        # Get service results from the proper field
        service_results = comprehensive_results.get('services', {})
        
        # Add comprehensive security information
        link_data.update({
            "safety_score": max(0, 100 - threat_score),  # Ensure safety score is between 0-100
            "threat_score": threat_score,
            "risk_level": risk_level,
            "threats": recommendations,
            "security_services": {}
        })
        
        # Add service-specific results
        for service_name, service_data in service_results.items():
            if service_data and not service_data.get('error'):
                # Handle different service result formats
                if service_name == 'virustotal':
                    positives = service_data.get('positives', 0)
                    total = service_data.get('total_scanners', 0)
                    details = "No detections"
                    if positives > 0:
                        if total > 0:
                            percentage = (positives/total)*100
                            details = f"{positives}/{total} malicious detections ({percentage:.1f}%)"
                            
                            # Aggiungi indicatori di gravità in base alla percentuale di rilevamento
                            if percentage > 10:
                                details += " - CRITICAL"
                            elif percentage > 5:
                                details += " - HIGH"
                            elif percentage > 0:
                                details += " - SUSPICIOUS"
                        else:
                            details = f"{positives} malicious detections - SUSPICIOUS"
                            
                        # Avviso più forte per URL shortener con rilevamenti
                        if is_shortener:
                            details += " - URL SHORTENER, HIGH RISK"
                            
                    link_data["security_services"][service_name] = {
                        "safe": service_data.get('is_safe', True),
                        "details": details,
                        "link": None
                    }
                elif service_name == 'phishtank':
                    pt_result = service_data.get('result', {})
                    if pt_result:
                        link_data["security_services"][service_name] = {
                            "safe": not pt_result.get('is_phish', False),
                            "details": "Verified phishing site" if pt_result.get('verified', False) else "Reported as phishing",
                            "link": None
                        }
                elif service_name == 'google_safe_browsing':
                    threats = service_data.get('threats', [])
                    is_safe = service_data.get('is_safe', True)
                    link_data["security_services"][service_name] = {
                        "safe": is_safe,
                        "details": f"Threats detected: {', '.join([t.get('threatType', 'Unknown') for t in threats])}" if threats else "No threats detected",
                        "link": None
                    }
                elif service_name in ['urlvoid', 'urlscan']:
                    result = service_data.get('result', {})
                    if result:
                        is_safe = result.get('is_safe', True)
                        link_data["security_services"][service_name] = {
                            "safe": is_safe,
                            "details": "Malicious content detected" if not is_safe else "No threats detected",
                            "link": None
                        }
    
    # Handle legacy single service results (fallback)
    elif safety_info:
        is_safe, detections, error = safety_info
        
        # Apply stricter checking for URL shorteners
        if is_shortener and detections and detections > 0:
            # Always consider URL shorteners with any detections as unsafe
            is_safe = False
        
        # Calculate safety score: 100 for safe, 0 for unsafe, 50 for unknown
        safety_score = 100 if is_safe else (0 if is_safe is not None else 50)
        
        # Add security information to the link data
        threats = []
        if detections:
            threats.append(f"{detections} malicious detections")
        
        if is_shortener:
            threats.append("URL shortener detected - consider analyzing the full destination URL")
        
        link_data.update({
            "safety_score": safety_score,
            "threat_score": 100 - safety_score,  # Ensure threat score is also set
            "risk_level": "Safe" if is_safe else ("High Risk" if is_shortener or (is_safe is not None and detections > 2) else "Medium Risk"),
            "threats": threats,
            "error": error if error else None
        })
        
    return link_data

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
                logger.debug(f"Error parsing plain text content: {e}")

    # Process, normalize and deduplicate links
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
    
    # Perform security investigation if requested
    if investigation and cleaned_links:
        logger.info(f"Starting safety investigation for {len(cleaned_links)} links...")
        investigation_start_time = time.time()
        
        # Process links in batches to avoid rate limit issues
        for i in range(0, len(cleaned_links), batch_size):
            batch = cleaned_links[i:i+batch_size]
            
            # Process each link in the current batch
            for link in batch:
                error = None  # Initialize error variable
                try:
                    # Add delay between batches to respect API limits
                    if i > 0 and i % batch_size == 0:
                        time.sleep(1)
                    
                    # Comprehensive URL analysis with multiple security services
                    try:
                        comprehensive_results = comprehensive_url_analysis(link)
                        
                        if comprehensive_results:
                            # Use comprehensive analysis results
                            link_data = create_link_data(link, comprehensive_results=comprehensive_results)
                        else:
                            # Fallback to single VirusTotal check
                            logger.warning(f"No comprehensive results for {link}, falling back to VirusTotal")
                            is_safe, detections, error = check_url_safety(link)
                            link_data = create_link_data(link, (is_safe, detections, error))
                            
                    except Exception as e:
                        logger.error(f"Error in comprehensive URL analysis for {link}: {e}")
                        # Fallback to single VirusTotal check
                        is_safe, detections, error = check_url_safety(link)
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

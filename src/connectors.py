"""
Connectors for external services like VirusTotal and DNS lookups.
"""

import dns.exception
import dns.resolver
import vt
import time
import os
import json
import requests
import hashlib
from datetime import datetime, timedelta
from config import (
    VIRUSTOTAL_API_KEY, 
    BLACKLISTS, 
    CACHE_DIR, 
    CACHE_EXPIRY_DAYS,
    URLSCAN_API_KEY,
    ABUSEIPDB_API_KEY
)

# Ensure cache directory exists
os.makedirs(CACHE_DIR, exist_ok=True)

# Cache for VirusTotal API calls
_vt_cache = {}

# Additional security services configurations
HYBRIDANALYSIS_API_KEY = os.getenv('HYBRIDANALYSIS_API_KEY', '')  # Hybrid Analysis API key
URLVOID_API_KEY = os.getenv('URLVOID_API_KEY', '')  # URLVoid API key

# Service URLs
URLSCAN_BASE_URL = "https://urlscan.io/api/v1/"
URLVOID_BASE_URL = "https://api.urlvoid.com/1000/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
HYBRIDANALYSIS_URL = "https://www.hybrid-analysis.com/api/v2/"

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
    Check if an IP is safe using VirusTotal with caching.
    
    Args:
        ip: The IP address to check
        
    Returns:
        Tuple (is_safe, positives, error) where is_safe is a boolean, positives is the number
        of malicious detections, and error is an error message or None
    """
    # Check cache first
    cache_result = _get_from_cache(ip, 'ip')
    if cache_result:
        return cache_result[0], cache_result[1], None
    
    max_retries = 2
    retry_delay = 2  # seconds
    
    for attempt in range(max_retries + 1):
        with vt.Client(VIRUSTOTAL_API_KEY) as client:
            try:
                analysis = client.get_object(f"/ip_addresses/{ip}")
                positives = analysis.last_analysis_stats.get('malicious', 0)
                is_safe = positives == 0
                
                # Cache the result
                _save_to_cache(ip, is_safe, positives, 'ip')
                
                return is_safe, positives, None
                
            except vt.error.APIError as e:
                error = str(e)
                
                # If it's a rate limit error and we have retries left
                if "QuotaExceededError" in error and attempt < max_retries:
                    time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                    continue
                # Log the error but don't propagate it
                print(f"Error making request to VirusTotal: {e}")
                return None, None, f"Error making request to VirusTotal: {e}"
            except Exception as e:
                print(f"Unexpected error checking IP safety: {str(e)}")
                return None, None, f"Unexpected error: {str(e)}"

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

def _get_from_cache(cache_key, cache_type='url'):
    """
    Retrieve data from local cache.
    
    Args:
        cache_key: Key for the cached item
        cache_type: Type of data being cached ('url', 'ip', or 'hash')
        
    Returns:
        Cached data or None if not found or expired
    """
    cache_path = os.path.join(CACHE_DIR, f"{cache_type}_{cache_key}.json")
    
    # Check in-memory cache first
    if cache_key in _vt_cache:
        return _vt_cache[cache_key]
    
    # If not in memory, check file cache
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
                
            # Check if cache is expired
            cache_time = datetime.fromisoformat(data['timestamp'])
            if datetime.now() - cache_time < timedelta(days=CACHE_EXPIRY_DAYS):
                # Add to memory cache and return
                _vt_cache[cache_key] = (data['is_safe'], data['positives'], None)
                return _vt_cache[cache_key]
        except (json.JSONDecodeError, KeyError, ValueError):
            # If cache file is corrupted, ignore it
            pass
    
    return None

def _save_to_cache(cache_key, is_safe, positives, cache_type='url'):
    """
    Save data to local cache.
    
    Args:
        cache_key: Key for the cached item
        is_safe: Safety status
        positives: Number of positive detections
        cache_type: Type of data being cached ('url', 'ip', or 'hash')
    """
    # Save to in-memory cache
    _vt_cache[cache_key] = (is_safe, positives, None)
    
    # Save to file cache
    cache_data = {
        'timestamp': datetime.now().isoformat(),
        'is_safe': is_safe,
        'positives': positives
    }
    
    cache_path = os.path.join(CACHE_DIR, f"{cache_type}_{cache_key}.json")
    try:
        with open(cache_path, 'w') as f:
            json.dump(cache_data, f)
    except Exception:
        # If saving to cache fails, just continue without caching
        pass

def check_url_safety(url):
    """
    Check if a URL is safe using VirusTotal with caching and retry logic.
    
    Args:
        url: The URL to check
        
    Returns:
        Tuple (is_safe, positives, error) where is_safe is a boolean,
        positives is the number of malicious detections, and error is an error message or None
    """
    # Generate a cache key (md5 of the URL)
    cache_key = hashlib.md5(url.encode()).hexdigest()
    
    # Check cache first
    cache_result = _get_from_cache(cache_key, 'url')
    if cache_result:
        return cache_result
    
    # If not in cache, query VirusTotal
    max_retries = 2
    retry_delay = 2  # seconds
    
    for attempt in range(max_retries + 1):
        with vt.Client(VIRUSTOTAL_API_KEY) as client:
            try:
                analysis = client.get_object(f"/urls/{vt.url_id(url)}")
                if hasattr(analysis, 'last_analysis_stats'):
                    positives = analysis.last_analysis_stats.get('malicious', 0)
                    is_safe = positives == 0
                    
                    # Cache the result
                    _save_to_cache(cache_key, is_safe, positives, 'url')
                    
                    return is_safe, positives, None
                else:
                    # If no analysis stats, consider it safe but log a warning
                    print(f"No analysis stats for URL: {url}")
                    _save_to_cache(cache_key, True, 0, 'url') # Cache as safe
                    return True, 0, "No analysis stats available"
                    
            except vt.error.APIError as e:
                error = str(e)
                if "QuotaExceededError" in error and attempt < max_retries:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                print(f"VirusTotal API error for URL {url}: {e}")
                return None, None, f"VirusTotal API error: {e}"
            except Exception as e:
                print(f"Unexpected error checking URL {url}: {str(e)}")
                return None, None, f"Unexpected error: {str(e)}"

def check_hash_safety(hash_value):
    """
    Check if a file hash is safe using VirusTotal with caching and retry logic.
    
    Args:
        hash_value: The hash (MD5, SHA1, or SHA256) to check.
        
    Returns:
        Tuple (is_safe, positives, error) where is_safe is a boolean,
        positives is the number of malicious detections, and error is an error message or None.
    """
    cache_key = hash_value
    
    # Check cache first
    cache_result = _get_from_cache(cache_key, 'hash')
    if cache_result:
        return cache_result

    max_retries = 2
    retry_delay = 2  # seconds

    for attempt in range(max_retries + 1):
        with vt.Client(VIRUSTOTAL_API_KEY) as client:
            try:
                # VirusTotal API expects the hash itself as the identifier for files
                analysis = client.get_object(f"/files/{hash_value}")
                
                if hasattr(analysis, 'last_analysis_stats'):
                    positives = analysis.last_analysis_stats.get('malicious', 0)
                    is_safe = positives == 0
                    
                    _save_to_cache(cache_key, is_safe, positives, 'hash')
                    return is_safe, positives, None
                else:
                    print(f"No analysis stats for hash: {hash_value}")
                    _save_to_cache(cache_key, True, 0, 'hash') # Cache as safe
                    return True, 0, "No analysis stats available"

            except vt.error.APIError as e:
                error = str(e)
                if "QuotaExceededError" in error and attempt < max_retries:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                # Specific handling for NotFoundError if the hash is not found
                if "NotFoundError" in error:
                    print(f"Hash {hash_value} not found on VirusTotal.")
                    _save_to_cache(cache_key, True, 0, 'hash') # Cache as safe (not found means not known malicious)
                    return True, 0, "Hash not found on VirusTotal"
                
                print(f"VirusTotal API error for hash {hash_value}: {e}")
                return None, None, f"VirusTotal API error: {e}"
            except Exception as e:
                print(f"Unexpected error checking hash {hash_value}: {str(e)}")
                return None, None, f"Unexpected error: {str(e)}"

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

# Alternative security services implementations

def check_phishtank_url(url):
    """
    Check if a URL is in PhishTank database.
    
    Args:
        url: The URL to check
        
    Returns:
        Tuple (is_phish, details, error)
    """
    try:
        data = {
            'url': url,
            'format': 'json'
        }
        
        response = requests.post(PHISHTANK_URL, data=data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            results = result.get('results', {})
            
            return {
                'is_phish': results.get('in_database', False),
                'verified': results.get('verified', False),
                'phish_id': results.get('phish_id'),
                'submission_time': results.get('submission_time')
            }, None
        
        return None, f"PhishTank error: {response.status_code}"
        
    except Exception as e:
        return None, f"PhishTank request failed: {str(e)}"

def check_urlscan_safety(url):
    """
    Submit URL to URLScan.io for analysis.
    
    Args:
        url: The URL to scan
        
    Returns:
        Tuple (scan_result, error)
    """
    if not URLSCAN_API_KEY:
        return None, "URLScan API key not configured"
    
    try:
        headers = {
            'API-Key': URLSCAN_API_KEY,
            'Content-Type': 'application/json'
        }
        
        data = {
            'url': url,
            'visibility': 'public'
        }
        
        # Submit URL for scanning
        scan_response = requests.post(
            f"{URLSCAN_BASE_URL}scan/",
            headers=headers,
            json=data,
            timeout=10
        )
        
        if scan_response.status_code == 200:
            scan_result = scan_response.json()
            uuid = scan_result.get('uuid')
            
            # Return scan UUID for later result retrieval
            return {
                'uuid': uuid,
                'api': scan_result.get('api'),
                'visibility': scan_result.get('visibility'),
                'url': scan_result.get('url'),
                'country': scan_result.get('country'),
                'message': 'Scan submitted successfully'
            }, None
        
        return None, f"URLScan error: {scan_response.status_code}"
        
    except Exception as e:
        return None, f"URLScan request failed: {str(e)}"

def check_urlvoid_safety(url):
    """
    Check URL reputation using URLVoid multi-engine scanner.
    
    Args:
        url: The URL to check
        
    Returns:
        Tuple (result, error)
    """
    if not URLVOID_API_KEY:
        return None, "URLVoid API key not configured"
    
    try:
        # Extract domain from URL for URLVoid
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        
        api_url = f"{URLVOID_BASE_URL}{URLVOID_API_KEY}/scan/{domain}/"
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            # URLVoid returns XML, need to parse it
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.content)
            
            # Extract basic information
            result = {
                'domain': domain,
                'engines_count': root.find('.//engines_count').text if root.find('.//engines_count') is not None else "0",
                'detections': root.find('.//detections').text if root.find('.//detections') is not None else "0",
                'scan_date': root.find('.//scan_date').text if root.find('.//scan_date') is not None else None
            }
            
            # Calculate safety
            detections = int(result['detections'])
            engines_count = int(result['engines_count'])
            
            result['is_safe'] = detections == 0
            result['detection_ratio'] = f"{detections}/{engines_count}"
            
            return result, None
        
        return None, f"URLVoid error: {response.status_code}"
        
    except Exception as e:
        return None, f"URLVoid request failed: {str(e)}"

def check_google_safe_browsing(url):
    """
    Check URL against Google Safe Browsing API.
    Note: Requires Google Safe Browsing API key
    
    Args:
        url: The URL to check
        
    Returns:
        Tuple (is_safe, threats, error)
    """
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    
    if not api_key:
        return None, None, "Google Safe Browsing API key not configured"
    
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        payload = {
            "client": {
                "clientId": "email-analyzer",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            
            if 'matches' in result:
                # Threats found
                threats = []
                for match in result['matches']:
                    threats.append({
                        'threatType': match.get('threatType'),
                        'platformType': match.get('platformType'),
                        'threatEntryType': match.get('threatEntryType')
                    })
                
                return False, threats, None
            else:
                # No threats found
                return True, [], None
        
        return None, None, f"Google Safe Browsing error: {response.status_code}"
        
    except Exception as e:
        return None, None, f"Google Safe Browsing request failed: {str(e)}"

def check_spamhaus_domain(domain):
    """
    Check domain against Spamhaus Domain Block List (DBL).
    
    Args:
        domain: The domain to check
        
    Returns:
        Tuple (is_listed, list_type, error)
    """
    try:
        # Spamhaus DBL query
        query = f"{domain}.zen.spamhaus.org"
        result = safe_resolve(query, 'A')
        
        if result:
            # Domain is listed in Spamhaus
            for answer in result:
                ip = str(answer)
                
                # Decode Spamhaus response codes
                if ip.startswith('127.0.1.'):
                    list_types = {
                        '127.0.1.2': 'SBL - Spamhaus Block List',
                        '127.0.1.3': 'SBL - Spamhaus Block List',
                        '127.0.1.9': 'XBL - Exploits Block List',
                        '127.0.1.10': 'XBL - Exploits Block List', 
                        '127.0.1.11': 'XBL - Exploits Block List'
                    }
                    
                    return True, list_types.get(ip, f'Listed with code {ip}'), None
            
            return True, 'Listed in Spamhaus', None
        
        return False, None, None
        
    except Exception as e:
        return None, None, f"Spamhaus check failed: {str(e)}"

def check_abuseipdb_enhanced(ip):
    """
    Enhanced AbuseIPDB check with detailed information.
    
    Args:
        ip: The IP address to check
        
    Returns:
        Tuple (result, error)
    """
    if not ABUSEIPDB_API_KEY:
        return None, "AbuseIPDB API key not configured"
    
    try:
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            data = result.get('data', {})
            
            return {
                'ip': data.get('ipAddress'),
                'abuse_confidence': data.get('abuseConfidencePercentage', 0),
                'country': data.get('countryCode'),
                'usage_type': data.get('usageType'),
                'isp': data.get('isp'),
                'domain': data.get('domain'),
                'total_reports': data.get('totalReports', 0),
                'num_distinct_users': data.get('numDistinctUsers', 0),
                'last_reported': data.get('lastReportedAt'),
                'is_whitelisted': data.get('isWhitelisted', False)
            }, None
        
        return None, f"AbuseIPDB error: {response.status_code}"
        
    except Exception as e:
        return None, f"AbuseIPDB request failed: {str(e)}"

def check_malwarebazaar_hash(hash_value):
    """
    Check hash against MalwareBazaar database.
    
    Args:
        hash_value: The hash to check (MD5, SHA1, or SHA256)
        
    Returns:
        Tuple (is_safe, details, error)
    """
    try:
        data = {
            'query': 'get_info',
            'hash': hash_value
        }
        
        response = requests.post(MALWAREBAZAAR_URL, data=data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get('query_status') == 'ok':
                # Hash found in MalwareBazaar = not safe
                malware_data = result.get('data', [])
                if malware_data:
                    sample = malware_data[0]  # Get first match
                    return False, {
                        'malware_family': sample.get('signature'),
                        'file_type': sample.get('file_type'),
                        'file_size': sample.get('file_size'),
                        'first_seen': sample.get('first_seen'),
                        'tags': sample.get('tags', [])
                    }, None
            else:
                # Hash not found = likely safe
                return True, {'status': 'not_found'}, None
                
        return None, None, f"MalwareBazaar error: {response.status_code}"
        
    except Exception as e:
        return None, None, f"MalwareBazaar request failed: {str(e)}"

def comprehensive_security_check(item, item_type='url'):
    """
    Perform comprehensive security check using multiple services.
    
    Args:
        item: The item to check (URL, IP, or hash)
        item_type: Type of item ('url', 'ip', 'hash')
        
    Returns:
        Dictionary with results from multiple services
    """
    results = {
        'item': item,
        'item_type': item_type,
        'overall_safe': True,
        'services': {}
    }
    
    if item_type == 'url':
        # Check URL with multiple services
        
        # VirusTotal
        vt_safe, vt_positives, vt_error = check_url_safety(item)
        if vt_safe is not None:
            results['services']['virustotal'] = {
                'safe': vt_safe,
                'positives': vt_positives,
                'error': vt_error
            }
            if not vt_safe:
                results['overall_safe'] = False
        
        # URLScan.io
        us_safe, us_details, us_error = check_urlscan_safety(item)
        if us_safe is not None:
            results['services']['urlscan'] = {
                'safe': us_safe,
                'details': us_details,
                'error': us_error
            }
        
        # URLVoid
        uv_safe, uv_details, uv_error = check_urlvoid_safety(item)
        if uv_safe is not None:
            results['services']['urlvoid'] = {
                'safe': uv_safe,
                'details': uv_details,
                'error': uv_error
            }
            if not uv_safe:
                results['overall_safe'] = False
        
        # PhishTank
        pt_safe, pt_details, pt_error = check_phishtank_url(item)
        if pt_safe is not None:
            results['services']['phishtank'] = {
                'safe': pt_safe,
                'details': pt_details,
                'error': pt_error
            }
            if not pt_safe:
                results['overall_safe'] = False
    
    elif item_type == 'ip':
        # Check IP with multiple services
        
        # VirusTotal
        vt_safe, vt_positives, vt_error = check_ip_safety(item)
        if vt_safe is not None:
            results['services']['virustotal'] = {
                'safe': vt_safe,
                'positives': vt_positives,
                'error': vt_error
            }
            if not vt_safe:
                results['overall_safe'] = False
        
        # Enhanced AbuseIPDB
        ab_safe, ab_details, ab_error = check_abuseipdb_enhanced(item)
        if ab_safe is not None:
            results['services']['abuseipdb'] = {
                'safe': ab_safe,
                'details': ab_details,
                'error': ab_error
            }
            if not ab_safe:
                results['overall_safe'] = False
    
    elif item_type == 'hash':
        # Check hash with multiple services
        
        # VirusTotal
        vt_safe, vt_positives, vt_error = check_hash_safety(item)
        if vt_safe is not None:
            results['services']['virustotal'] = {
                'safe': vt_safe,
                'positives': vt_positives,
                'error': vt_error
            }
            if not vt_safe:
                results['overall_safe'] = False
        
        # MalwareBazaar
        mb_safe, mb_details, mb_error = check_malwarebazaar_hash(item)
        if mb_safe is not None:
            results['services']['malwarebazaar'] = {
                'safe': mb_safe,
                'details': mb_details,
                'error': mb_error
            }
            if not mb_safe:
                results['overall_safe'] = False
    
    return results

def comprehensive_url_analysis(url):
    """
    Perform comprehensive URL analysis using multiple security services.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary with results from multiple services
    """
    results = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'services': {}
    }
    
    # VirusTotal
    vt_safe, vt_positives, vt_error = check_url_safety(url)
    results['services']['virustotal'] = {
        'is_safe': vt_safe,
        'positives': vt_positives,
        'error': vt_error
    }
    
    # PhishTank
    pt_result, pt_error = check_phishtank_url(url)
    results['services']['phishtank'] = {
        'result': pt_result,
        'error': pt_error
    }
    
    # URLVoid (if API key available)
    uv_result, uv_error = check_urlvoid_safety(url)
    results['services']['urlvoid'] = {
        'result': uv_result,
        'error': uv_error
    }
    
    # Google Safe Browsing (if API key available)
    gsb_safe, gsb_threats, gsb_error = check_google_safe_browsing(url)
    results['services']['google_safe_browsing'] = {
        'is_safe': gsb_safe,
        'threats': gsb_threats,
        'error': gsb_error
    }
    
    # URLScan.io (if API key available)
    us_result, us_error = check_urlscan_safety(url)
    results['services']['urlscan'] = {
        'result': us_result,
        'error': us_error
    }
    
    # Calculate overall risk score
    risk_score = calculate_url_risk_score(results)
    results['risk_score'] = risk_score
    results['recommendation'] = get_url_recommendation(risk_score)
    
    return results

def comprehensive_hash_analysis(hash_value):
    """
    Perform comprehensive hash analysis using multiple security services.
    
    Args:
        hash_value: The hash to analyze
        
    Returns:
        Dictionary with results from multiple services
    """
    results = {
        'hash': hash_value,
        'timestamp': datetime.now().isoformat(),
        'services': {}
    }
    
    # VirusTotal
    vt_safe, vt_positives, vt_error = check_hash_safety(hash_value)
    results['services']['virustotal'] = {
        'is_safe': vt_safe,
        'positives': vt_positives,
        'error': vt_error
    }
    
    # MalwareBazaar
    mb_safe, mb_details, mb_error = check_malwarebazaar_hash(hash_value)
    results['services']['malwarebazaar'] = {
        'is_safe': mb_safe,
        'details': mb_details,
        'error': mb_error
    }
    
    # Calculate overall risk score
    risk_score = calculate_hash_risk_score(results)
    results['risk_score'] = risk_score
    results['recommendation'] = get_hash_recommendation(risk_score)
    
    return results

def calculate_url_risk_score(analysis_results):
    """
    Calculate risk score for URL based on multiple service results.
    
    Args:
        analysis_results: Results from comprehensive_url_analysis
        
    Returns:
        Risk score from 0 (safe) to 10 (very dangerous)
    """
    score = 0
    services = analysis_results.get('services', {})
    
    # VirusTotal weight: 3 points
    vt = services.get('virustotal', {})
    if not vt.get('is_safe') and vt.get('positives', 0) > 0:
        score += min(3, vt.get('positives', 0) / 10 * 3)
    
    # PhishTank weight: 4 points (high for phishing)
    pt = services.get('phishtank', {}).get('result')
    if pt and pt.get('is_phish'):
        score += 4
    
    # URLVoid weight: 2 points
    uv = services.get('urlvoid', {}).get('result')
    if uv and not uv.get('is_safe'):
        detections = int(uv.get('detections', 0))
        engines = int(uv.get('engines_count', 1))
        score += min(2, (detections / engines) * 2)
    
    # Google Safe Browsing weight: 3 points
    gsb = services.get('google_safe_browsing', {})
    if not gsb.get('is_safe') and gsb.get('threats'):
        score += 3
    
    return min(10, score)

def calculate_hash_risk_score(analysis_results):
    """
    Calculate risk score for hash based on multiple service results.
    
    Args:
        analysis_results: Results from comprehensive_hash_analysis
        
    Returns:
        Risk score from 0 (safe) to 10 (very dangerous)
    """
    score = 0
    services = analysis_results.get('services', {})
    
    # VirusTotal weight: 4 points
    vt = services.get('virustotal', {})
    if not vt.get('is_safe') and vt.get('positives', 0) > 0:
        score += min(4, vt.get('positives', 0) / 10 * 4)
    
    # MalwareBazaar weight: 6 points (high because it's specialized)
    mb = services.get('malwarebazaar', {})
    if not mb.get('is_safe'):
        score += 6
    
    return min(10, score)

def get_url_recommendation(risk_score):
    """Get recommendation based on URL risk score."""
    if risk_score >= 7:
        return "BLOCK - High risk URL, likely malicious"
    elif risk_score >= 4:
        return "CAUTION - Medium risk, investigate further"
    elif risk_score >= 1:
        return "WARNING - Low risk, monitor carefully"
    else:
        return "SAFE - No threats detected"

def get_hash_recommendation(risk_score):
    """Get recommendation based on hash risk score."""
    if risk_score >= 7:
        return "QUARANTINE - High risk file, likely malware"
    elif risk_score >= 4:
        return "CAUTION - Medium risk, scan with additional tools"
    elif risk_score >= 1:
        return "WARNING - Low risk, monitor file behavior"
    else:
        return "SAFE - No malware signatures detected"
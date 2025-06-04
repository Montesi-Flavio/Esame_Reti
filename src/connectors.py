"""
Connectors for external services like VirusTotal and DNS lookups.
"""

import dns.exception
import dns.resolver
import vt
import time
import os
import json
from datetime import datetime, timedelta
from config import VIRUSTOTAL_API_KEY, BLACKLISTS, CACHE_DIR, CACHE_EXPIRY_DAYS

# Ensure cache directory exists
os.makedirs(CACHE_DIR, exist_ok=True)

# Cache for VirusTotal API calls
_vt_cache = {}

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
    
    client = vt.Client(VIRUSTOTAL_API_KEY)
    max_retries = 2
    retry_delay = 2  # seconds
    
    for attempt in range(max_retries + 1):
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
        finally:
            if attempt == max_retries:
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
    import hashlib
    cache_key = hashlib.md5(url.encode()).hexdigest()
    
    # Check cache first
    cache_result = _get_from_cache(cache_key, 'url')
    if cache_result:
        return cache_result
    
    # If not in cache, query VirusTotal
    client = vt.Client(VIRUSTOTAL_API_KEY)
    max_retries = 2
    retry_delay = 2  # seconds
    
    for attempt in range(max_retries + 1):
        try:
            analysis = client.get_object(f"/urls/{vt.url_id(url)}")
            if hasattr(analysis, 'last_analysis_stats'):
                positives = analysis.last_analysis_stats.get('malicious', 0)
                is_safe = positives == 0
                
                # Cache the result
                _save_to_cache(cache_key, is_safe, positives, 'url')
                
                return is_safe, positives, None
            else:
                return None, None, "No analysis data available"
        except vt.error.APIError as e:
            error = str(e)
            
            # If it's a rate limit error and we have retries left
            if "QuotaExceededError" in error and attempt < max_retries:
                time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                continue
            
            return None, None, f"Error making request to VirusTotal: {e}"
        except Exception as e:
            return None, None, f"Unexpected error: {str(e)}"
        finally:
            if attempt == max_retries:
                client.close()

def check_hash_safety(hash_value):
    """
    Check if a file hash is safe using VirusTotal with caching.
    
    Args:
        hash_value: The hash value to check
        
    Returns:
        Tuple (is_safe, positives, error) where is_safe is a boolean,
        positives is the number of malicious detections, and error is an error message or None
    """
    # Check cache first
    cache_result = _get_from_cache(hash_value, 'hash')
    if cache_result:
        return cache_result
    
    client = vt.Client(VIRUSTOTAL_API_KEY)
    max_retries = 2
    retry_delay = 2  # seconds
    
    for attempt in range(max_retries + 1):
        try:
            analysis = client.get_object(f"/files/{hash_value}")
            positives = analysis.last_analysis_stats.get('malicious', 0)
            is_safe = positives == 0
            
            # Cache the result
            _save_to_cache(hash_value, is_safe, positives, 'hash')
            
            return is_safe, positives, None
            
        except vt.error.APIError as e:
            error = str(e)
            
            # If it's a rate limit error and we have retries left
            if "QuotaExceededError" in error and attempt < max_retries:
                time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                continue
            
            return None, None, f"Error making request to VirusTotal: {e}"
        except Exception as e:
            return None, None, f"Unexpected error: {str(e)}"
        finally:
            if attempt == max_retries:
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
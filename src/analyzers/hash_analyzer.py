"""
File hash analysis and computation functionality.
"""

import hashlib
from connectors import check_hash_safety

def calculate_hashes(email_file, investigation=False):
    """
    Calculate file hashes for an email file and optionally investigate them.
    
    Args:
        email_file: Path to the email file
        investigation: Whether to perform security investigation
        
    Returns:
        Dictionary with hash data and optional investigation results
    """
    # Read file and calculate hashes
    with open(email_file, 'rb') as f:
        file_data = f.read()
        
    # Generate hash values
    hashes = {
        "File MD5": hashlib.md5(file_data).hexdigest(),
        "File SHA1": hashlib.sha1(file_data).hexdigest(),
        "File SHA256": hashlib.sha256(file_data).hexdigest()
    }

    # Perform investigation if requested
    investigation_data = {}
    if investigation:
        for hash_type, hash_value in hashes.items():
            safe, positives, error = check_hash_safety(hash_value)
            
            if error:
                investigation_data[hash_type] = {
                    "Error": error
                }
            else:
                investigation_data[hash_type] = {
                    "Virustotal": f"https://www.virustotal.com/gui/file/{hash_value}",
                    "Safety": "Safe" if safe else "Unsafe",
                    "Positives": positives
                }
    
    return {"Data": hashes, "Investigation": investigation_data}
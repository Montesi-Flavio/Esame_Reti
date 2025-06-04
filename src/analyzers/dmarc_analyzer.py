"""
DMARC analysis functionality for email authentication verification.
"""

import re
import logging
import dns.resolver
from email.parser import HeaderParser

# Configure logging
logger = logging.getLogger('email_analyzer.dmarc_analyzer')


def analyze_dmarc(mail_data, investigation=False):
    """
    Analyze DMARC policy and authentication results for an email.
    
    Args:
        mail_data: Email data as string
        investigation: Whether to perform detailed DMARC investigation
        
    Returns:
        Dictionary with DMARC analysis data
    """
    headers = HeaderParser().parsestr(mail_data, headersonly=True)
    dmarc_data = {"Data": {}, "Investigation": {}}
    
    # Extract relevant authentication headers
    auth_headers = {
        "dmarc": headers.get('Authentication-Results', ''),
        "dkim": headers.get('DKIM-Signature', ''),
        "spf": headers.get('Received-SPF', ''),
        "from_domain": extract_domain_from_header(headers.get('From', '')),
        "return_path": headers.get('Return-Path', ''),
        "reply_to": headers.get('Reply-To', '')
    }
      # Basic DMARC data
    dmarc_data["Data"] = {
        "From_Domain": auth_headers["from_domain"],
        "DKIM_Present": bool(auth_headers["dkim"]),
        "SPF_Present": bool(auth_headers["spf"]),
        "Authentication_Results": auth_headers["dmarc"]
    }
    
    # Parse authentication results for DMARC status
    if auth_headers["dmarc"]:
        dmarc_result = parse_authentication_results(auth_headers["dmarc"])
        dmarc_data["Data"].update(dmarc_result)
      # Analyze DKIM signature if present
    dkim_analysis = {}
    if auth_headers["dkim"]:
        dkim_analysis = analyze_dkim_signature(auth_headers["dkim"])
        dmarc_data["Data"]["DKIM_Analysis"] = dkim_analysis
    
    # Perform investigation if requested
    if investigation and auth_headers["from_domain"]:
        investigation_data = investigate_dmarc_policy(auth_headers["from_domain"])
        
        # Add DKIM domain investigation if DKIM is present
        if auth_headers["dkim"] and investigation:
            dkim_domain = dkim_analysis.get("Domain", auth_headers["from_domain"])
            if dkim_domain and dkim_domain != auth_headers["from_domain"]:
                investigation_data["DKIM_Domain_Investigation"] = investigate_dkim_domain(dkim_domain)
        
        dmarc_data["Investigation"] = investigation_data
    
    return dmarc_data


def extract_domain_from_header(from_header):
    """
    Extract domain from From header.
    
    Args:
        from_header: The From header value
        
    Returns:
        Domain string or empty string if not found
    """
    if not from_header:
        return ""
    
    # Extract email address from header (handle formats like "Name <email@domain.com>")
    email_match = re.search(r'<([^>]+)>', from_header)
    if email_match:
        email = email_match.group(1)
    else:
        # Try to find email pattern directly
        email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', from_header)
        if email_match:
            email = email_match.group(1)
        else:
            return ""
    
    # Extract domain from email
    if '@' in email:
        return email.split('@')[1].lower()
    return ""


def parse_authentication_results(auth_results):
    """
    Parse Authentication-Results header for DMARC, SPF, and DKIM status.
    
    Args:
        auth_results: Authentication-Results header value
        
    Returns:
        Dictionary with parsed authentication status
    """
    results = {
        "DMARC_Status": "not_found",
        "SPF_Status": "not_found", 
        "DKIM_Status": "not_found",
        "DMARC_Policy": "none"
    }
    
    if not auth_results:
        return results
    
    # Parse DMARC result
    dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
    if dmarc_match:
        results["DMARC_Status"] = dmarc_match.group(1).lower()
    
    # Parse SPF result
    spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
    if spf_match:
        results["SPF_Status"] = spf_match.group(1).lower()
    
    # Parse DKIM result
    dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
    if dkim_match:
        results["DKIM_Status"] = dkim_match.group(1).lower()
    
    # Extract policy if present
    policy_match = re.search(r'policy\.(\w+)=(\w+)', auth_results, re.IGNORECASE)
    if policy_match:
        results["DMARC_Policy"] = policy_match.group(2).lower()
    
    return results


def investigate_dmarc_policy(domain):
    """
    Investigate DMARC policy for a domain by querying DNS.
    
    Args:
        domain: Domain to investigate
        
    Returns:
        Dictionary with DMARC policy investigation results
    """
    investigation = {
        "Domain": domain,
        "DMARC_Record": "not_found",
        "Policy": "none",
        "Subdomain_Policy": "none", 
        "Percentage": 100,
        "Aggregate_Reports": [],
        "Forensic_Reports": [],
        "Safety_Assessment": "unknown"
    }
    
    try:
        # Query DMARC record
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        
        for answer in answers:
            record = str(answer).strip('"')
            if record.startswith('v=DMARC1'):
                investigation["DMARC_Record"] = record
                investigation.update(parse_dmarc_record(record))
                break
        
        # Assess safety based on policy
        investigation["Safety_Assessment"] = assess_dmarc_safety(investigation)
        
    except dns.resolver.NXDOMAIN:
        investigation["DMARC_Record"] = "domain_not_found"
    except dns.resolver.NoAnswer:
        investigation["DMARC_Record"] = "no_dmarc_record"
    except Exception as e:
        investigation["DMARC_Record"] = f"error: {str(e)}"
    
    return investigation


def parse_dmarc_record(record):
    """
    Parse DMARC DNS record.
    
    Args:
        record: DMARC TXT record value
        
    Returns:
        Dictionary with parsed DMARC policy components
    """
    parsed = {}
    
    # Extract policy
    policy_match = re.search(r'p=(\w+)', record)
    if policy_match:
        parsed["Policy"] = policy_match.group(1).lower()
    
    # Extract subdomain policy
    sp_match = re.search(r'sp=(\w+)', record)
    if sp_match:
        parsed["Subdomain_Policy"] = sp_match.group(1).lower()
    else:
        parsed["Subdomain_Policy"] = parsed.get("Policy", "none")
    
    # Extract percentage
    pct_match = re.search(r'pct=(\d+)', record)
    if pct_match:
        parsed["Percentage"] = int(pct_match.group(1))
    
    # Extract aggregate report URIs
    rua_match = re.search(r'rua=([^;]+)', record)
    if rua_match:
        parsed["Aggregate_Reports"] = [uri.strip() for uri in rua_match.group(1).split(',')]
    
    # Extract forensic report URIs
    ruf_match = re.search(r'ruf=([^;]+)', record)
    if ruf_match:
        parsed["Forensic_Reports"] = [uri.strip() for uri in ruf_match.group(1).split(',')]
    
    return parsed


def assess_dmarc_safety(dmarc_info):
    """
    Assess safety level based on DMARC configuration.
    
    Args:
        dmarc_info: Dictionary with DMARC policy information
        
    Returns:
        Safety assessment string
    """
    policy = dmarc_info.get("Policy", "none").lower()
    percentage = dmarc_info.get("Percentage", 100)
    has_record = dmarc_info.get("DMARC_Record", "") not in ["not_found", "no_dmarc_record", "domain_not_found"]
    
    if not has_record:
        return "high_risk"  # No DMARC record
    elif policy == "reject" and percentage >= 100:
        return "secure"     # Strong policy, full enforcement
    elif policy == "quarantine" and percentage >= 50:
        return "moderate"   # Moderate policy
    elif policy in ["reject", "quarantine"] and percentage < 50:
        return "weak"       # Policy exists but low enforcement
    else:
        return "vulnerable" # No policy or very weak


def analyze_dkim_signature(dkim_header):
    """
    Analyze DKIM signature header for detailed information.
    
    Args:
        dkim_header: DKIM-Signature header value
        
    Returns:
        Dictionary with DKIM signature analysis
    """
    dkim_data = {
        "Version": "unknown",
        "Algorithm": "unknown", 
        "Domain": "unknown",
        "Selector": "unknown",
        "Canonicalization": "unknown",
        "Headers_Signed": [],
        "Body_Hash": "present" if "bh=" in dkim_header else "missing",
        "Signature": "present" if "b=" in dkim_header else "missing",
        "Validity": "unknown"
    }
    
    if not dkim_header:
        return dkim_data
    
    # Extract version
    version_match = re.search(r'v=([^;]+)', dkim_header)
    if version_match:
        dkim_data["Version"] = version_match.group(1).strip()
    
    # Extract algorithm
    algo_match = re.search(r'a=([^;]+)', dkim_header)
    if algo_match:
        dkim_data["Algorithm"] = algo_match.group(1).strip()
    
    # Extract domain
    domain_match = re.search(r'd=([^;]+)', dkim_header)
    if domain_match:
        dkim_data["Domain"] = domain_match.group(1).strip()
    
    # Extract selector
    selector_match = re.search(r's=([^;]+)', dkim_header)
    if selector_match:
        dkim_data["Selector"] = selector_match.group(1).strip()
    
    # Extract canonicalization
    canon_match = re.search(r'c=([^;]+)', dkim_header)
    if canon_match:
        dkim_data["Canonicalization"] = canon_match.group(1).strip()
    
    # Extract signed headers
    headers_match = re.search(r'h=([^;]+)', dkim_header)
    if headers_match:
        headers_list = headers_match.group(1).strip().split(':')
        dkim_data["Headers_Signed"] = [h.strip() for h in headers_list if h.strip()]
    
    # Check for required components
    dkim_data["Validity"] = assess_dkim_validity(dkim_data, dkim_header)
    
    return dkim_data


def assess_dkim_validity(dkim_data, dkim_header):
    """
    Assess the validity of DKIM signature components.
    
    Args:
        dkim_data: Parsed DKIM data
        dkim_header: Original DKIM header
        
    Returns:
        Validity assessment string
    """
    issues = []
    
    # Check version
    if dkim_data["Version"] != "1":
        issues.append("Invalid or missing version")
    
    # Check algorithm
    if dkim_data["Algorithm"] == "unknown" or not dkim_data["Algorithm"]:
        issues.append("Missing algorithm")
    elif not any(alg in dkim_data["Algorithm"].lower() for alg in ["rsa", "ed25519"]):
        issues.append("Unsupported algorithm")
    
    # Check domain
    if dkim_data["Domain"] == "unknown" or not dkim_data["Domain"]:
        issues.append("Missing domain")
    
    # Check selector
    if dkim_data["Selector"] == "unknown" or not dkim_data["Selector"]:
        issues.append("Missing selector")
    
    # Check required headers
    required_headers = ["from"]
    signed_headers_lower = [h.lower() for h in dkim_data["Headers_Signed"]]
    for req_header in required_headers:
        if req_header not in signed_headers_lower:
            issues.append(f"Required header '{req_header}' not signed")
    
    # Check body hash
    if dkim_data["Body_Hash"] == "missing":
        issues.append("Missing body hash")
    
    # Check signature
    if dkim_data["Signature"] == "missing":
        issues.append("Missing signature")
    
    # Return assessment
    if not issues:
        return "valid_structure"
    elif len(issues) <= 2:
        return "minor_issues"
    else:
        return "major_issues"


def investigate_dkim_domain(domain):
    """
    Investigate DKIM configuration for a domain.
    
    Args:
        domain: Domain to investigate
        
    Returns:
        Dictionary with DKIM domain investigation results
    """
    investigation = {
        "Domain": domain,
        "Common_Selectors_Found": [],
        "DKIM_Records_Found": 0,
        "Assessment": "unknown"
    }
    
    # Common DKIM selectors to check
    common_selectors = [
        "default", "google", "k1", "k2", "dkim", "mail", 
        "email", "selector1", "selector2", "s1", "s2",
        "20230601", "202306", "2023"  # Common date-based selectors
    ]
    
    found_records = 0
    found_selectors = []
    
    try:
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                
                for answer in answers:
                    record = str(answer).strip('"')
                    if 'k=' in record and 'p=' in record:  # Valid DKIM record indicators
                        found_records += 1
                        found_selectors.append(selector)
                        break
                        
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                continue
                
        investigation["DKIM_Records_Found"] = found_records
        investigation["Common_Selectors_Found"] = found_selectors
        
        # Assess DKIM configuration
        if found_records == 0:
            investigation["Assessment"] = "no_dkim_records"
        elif found_records >= 3:
            investigation["Assessment"] = "strong_dkim_setup"
        elif found_records >= 1:
            investigation["Assessment"] = "basic_dkim_setup"
        
    except Exception as e:
        investigation["Assessment"] = f"investigation_error: {str(e)}"
    
    return investigation

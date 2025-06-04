"""
Convert JSON analysis results to HTML.
"""

import json
from html import escape
import os

# Handle imports for both standalone and module usage
try:
    from .styles import get_base_styles
except ImportError:
    # Fallback for standalone execution
    import sys
    sys.path.append(os.path.dirname(__file__))
    from styles import get_base_styles

def read_json_data(json_file):
    """
    Read analysis data from JSON file.
    
    Args:
        json_file: Path to the JSON file
        
    Returns:
        List of analysis results
    """
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        return []

def format_hash_value(hash_data):
    """
    Format hash data for HTML display.
    
    Args:
        hash_data: Hash data which can be a string or dictionary
        
    Returns:
        Formatted string for HTML display
    """
    if isinstance(hash_data, str):
        return escape(hash_data)
    elif isinstance(hash_data, dict):
        # If it's a dictionary with investigation results
        result = escape(hash_data.get('hash', ''))
        if hash_data.get('is_safe') is not None:
            safety = "Safe" if hash_data['is_safe'] else "Unsafe"
            result += f' <span class="badge badge-{"success" if hash_data["is_safe"] else "danger"}">{safety}</span>'
        if hash_data.get('detections'):
            result += f' <div class="threats">Detections: {escape(str(hash_data["detections"]))}</div>'
        return result
    return ''

def generate_html_from_json(json_file):
    """
    Generate HTML from JSON analysis results.
    
    Args:
        json_file: Path to the JSON file
        
    Returns:
        Complete HTML page as string
    """
    data = read_json_data(json_file)
    if not data:
        return "<h1>No analysis data available</h1>"
        
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Analysis Results</title>
        {get_base_styles()}
    </head>
    <body>
        <div class="container">
            <h1>Email Analysis Results</h1>    """
    
    # Generate tabs for each email
    html += '\n    <div class="tab-container">\n'
    for i, result in enumerate(data):
        active = " active" if i == 0 else ""
        html += f'        <button class="tab{active}" onclick="showEmail({i})">Email {i+1}</button>\n'
    html += '    </div>\n'
      # Generate content for each email
    for i, result in enumerate(data):
        active = " active" if i == 0 else ""
        html += f'\n    <div id="email-{i}" class="email-content{active}">\n'
        
        # Headers section with enhanced display
        if "Headers" in result and "Headers" in result["Headers"]:
            headers = result["Headers"]["Headers"]
            html += '        <div class="section">\n'
            html += '            <h3>📧 Email Headers</h3>\n'
            
            if "HTML_View" in headers:
                # Display formatted headers from header analyzer
                html += '            <div class="headers-container">\n'
                for key, value in headers["HTML_View"].items():
                    if key == "Dettagli Tecnici":
                        # Special handling for accordion-style technical details
                        html += f'''<div class="header-section-expandable">
                            <details>
                                <summary>🔧 {escape(key)}</summary>
                                <div class="expandable-content">{value}</div>
                            </details>
                        </div>'''
                    else:
                        html += f'''<div class="header-item">
                            <div class="header-label">{escape(key)}:</div>
                            <div class="header-value">{value}</div>
                        </div>'''
                html += '</div>'
            elif "Data" in headers:
                # Fallback to basic headers display
                html += '<div class="headers-basic">'
                for key, value in headers["Data"].items():
                    if key in ['subject', 'from', 'to', 'date', 'message-id']:
                        html += f'<div class="header-item"><strong>{escape(key.title())}:</strong> {escape(str(value))}</div>'
                html += '</div>'
            
            html += '</div>'
        
        # Links section
        if "Links" in result and "Links" in result["Links"]:
            html += '<div class="section">'
            html += '<h3>🔗 Links Analysis</h3>'
            links = result["Links"]["Links"]
            if links.get("unique_links"):
                html += f'<p>Found {links["total_links"]} unique links</p>'
                html += '<div class="link-list">'
                for link in links["unique_links"]:
                    safety_class = ""
                    if "safety_score" in link:
                        if link["safety_score"] >= 80:
                            safety_class = " safe-link"
                        elif link["safety_score"] >= 50:
                            safety_class = " warning-link"
                        else:
                            safety_class = " danger-link"
                    
                    html += f'<div class="link-item{safety_class}">'
                    html += f'<div class="link-url"><a href="{escape(link["url"])}" target="_blank">{escape(link["url"])}</a></div>'
                    html += '<div class="link-details">'
                    html += f'<span class="domain-info">Domain: {escape(link["domain"])}</span>'
                    if "safety_score" in link:
                        html += f'<div>Safety Score: {link["safety_score"]}%</div>'
                    if link.get("threats"):
                        html += f'<div class="threats">Threats: {", ".join(escape(str(t)) for t in link["threats"])}</div>'
                    if link.get("error"):
                        html += f'<div class="threats">Error: {escape(link["error"])}</div>'
                    html += '</div></div>'
                html += '</div>'
            else:
                html += '<p>No links found in this email</p>'
            html += '</div>'
        
        # Attachments section
        if "Attachments" in result and "Attachments" in result["Attachments"]:
            attachments = result["Attachments"]["Attachments"]
            html += '<div class="section">'
            html += '<h3>📎 Attachments Analysis</h3>'
            
            # Check if there are attachments
            if "Allegati" in attachments and attachments["Allegati"]:
                # Warning message if present
                if "Avviso" in attachments:
                    alert_class = "danger" if "ATTENZIONE" in attachments["Avviso"] else "info"
                    html += f'''<div class="alert alert-{alert_class}">
                        <strong>⚠️ Warning:</strong> {escape(attachments["Avviso"])}
                    </div>'''
                
                html += '<div class="attachments-container">'
                
                for attachment_id, attachment in attachments["Allegati"].items():
                    # Determine safety status
                    is_suspicious = attachment.get("Sospetto", "No") == "Sì - File eseguibile (.exe/.bat)"
                    safety_class = "danger" if is_suspicious else "success"
                    safety_icon = "🚨" if is_suspicious else "✅"
                    
                    html += f'''<div class="attachment-card">
                        <div class="attachment-header">
                            <div class="attachment-name">
                                {safety_icon} <strong>{escape(attachment.get("Filename", "Unknown"))}</strong>
                            </div>
                            <span class="badge badge-{safety_class}">
                                {escape(attachment.get("Sospetto", "Unknown"))}
                            </span>
                        </div>
                        <div class="attachment-details">
                            <div class="attachment-info">
                                <strong>Type:</strong> {escape(attachment.get("MIME Type", "Unknown"))}<br>
                                <strong>Size:</strong> {escape(attachment.get("Size", "Unknown"))}<br>
                                <strong>Email ID:</strong> {escape(str(attachment.get("Email ID", "Unknown")))}
                            </div>
                            
                            <div class="hash-section">
                                <details>
                                    <summary>🔐 File Hashes</summary>
                                    <div class="hash-content">
                                        <div class="hash-item">
                                            <span class="hash-label">MD5:</span>
                                            <code class="hash-value">
                                                <a href="https://www.virustotal.com/gui/file/{attachment.get("MD5", "")}" target="_blank" title="Check on VirusTotal">
                                                    {escape(attachment.get("MD5", ""))}
                                                </a>
                                            </code>
                                        </div>
                                        <div class="hash-item">
                                            <span class="hash-label">SHA1:</span>
                                            <code class="hash-value">
                                                <a href="https://www.virustotal.com/gui/file/{attachment.get("SHA1", "")}" target="_blank" title="Check on VirusTotal">
                                                    {escape(attachment.get("SHA1", ""))}
                                                </a>
                                            </code>
                                        </div>
                                        <div class="hash-item">
                                            <span class="hash-label">SHA256:</span>
                                            <code class="hash-value">
                                                <a href="https://www.virustotal.com/gui/file/{attachment.get("SHA256", "")}" target="_blank" title="Check on VirusTotal">
                                                    {escape(attachment.get("SHA256", ""))}
                                                </a>
                                            </code>
                                        </div>
                                    </div>
                                </details>
                            </div>'''
                    
                    # Add security analysis if available
                    if "Stato Sicurezza" in attachment:
                        security_safe = "Sicuro" in attachment["Stato Sicurezza"]
                        security_class = "success" if security_safe else "danger"
                        security_icon = "🛡️" if security_safe else "⚠️"
                        
                        html += f'''<div class="security-analysis">
                            <h5>{security_icon} Security Analysis</h5>
                            <span class="badge badge-{security_class}">
                                {escape(attachment["Stato Sicurezza"])}
                            </span>'''
                        
                        if "Dettagli Sicurezza" in attachment:
                            html += '<div class="security-details"><ul>'
                            for detail in attachment["Dettagli Sicurezza"]:
                                html += f'<li>{escape(detail)}</li>'
                            html += '</ul></div>'
                        
                        html += '</div>'
                    
                    # Add file path if available
                    if "File Path" in attachment:
                        file_path = attachment["File Path"]
                        file_name = os.path.basename(file_path)
                        html += f'''<div class="file-link">
                            <strong>📁 Saved as:</strong> 
                            <a href="attachments/{escape(file_name)}" target="_blank">{escape(file_name)}</a>
                        </div>'''
                    
                    html += '</div>'  # Close attachment-card
                
                html += '</div>'  # Close attachments-container
            else:
                html += '''<div class="alert alert-info">
                    <strong>📎 No attachments found in this email</strong>
                </div>'''
            
            html += '</div>'  # Close section
          # DMARC Authentication section
        if "DMARC" in result and "DMARC" in result["DMARC"]:
            dmarc_data = result["DMARC"]["DMARC"]
            html += '<div class="section">'
            html += '<h3>🔐 DMARC & DKIM Authentication Analysis</h3>'
            
            if dmarc_data:
                html += '<div class="dmarc-container">'
                
                # Display domain information
                if "Data" in dmarc_data:
                    data_section = dmarc_data["Data"]
                    from_domain = data_section.get("From_Domain", "Unknown")
                    
                    html += f'''<div class="domain-info">
                        <h4>📧 Domain Analysis: {escape(from_domain)}</h4>
                    </div>'''
                    
                    # DKIM Analysis Section
                    dkim_present = data_section.get("DKIM_Present", False)
                    html += f'''<div class="dkim-analysis">
                        <h5>🔑 DKIM (DomainKeys Identified Mail) Analysis</h5>
                        <div class="auth-status-box">'''
                    
                    if dkim_present:
                        html += '''<div class="status-item success">
                            <span class="status-icon">✅</span>
                            <span class="status-text">DKIM Signature Present</span>
                        </div>'''
                        
                        # Display detailed DKIM analysis if available
                        if "DKIM_Analysis" in data_section:
                            dkim_analysis = data_section["DKIM_Analysis"]
                            html += '''<div class="dkim-details">
                                <h6>📋 DKIM Signature Details</h6>
                                <div class="dkim-details-grid">'''
                            
                            # Version
                            if "Version" in dkim_analysis:
                                html += f'''<div class="detail-item">
                                    <span class="detail-label">Version:</span>
                                    <span class="detail-value">{escape(str(dkim_analysis["Version"]))}</span>
                                </div>'''
                            
                            # Algorithm
                            if "Algorithm" in dkim_analysis:
                                html += f'''<div class="detail-item">
                                    <span class="detail-label">Algorithm:</span>
                                    <span class="detail-value"><code>{escape(str(dkim_analysis["Algorithm"]))}</code></span>
                                </div>'''
                            
                            # Domain
                            if "Domain" in dkim_analysis:
                                html += f'''<div class="detail-item">
                                    <span class="detail-label">Signing Domain:</span>
                                    <span class="detail-value"><strong>{escape(str(dkim_analysis["Domain"]))}</strong></span>
                                </div>'''
                            
                            # Selector
                            if "Selector" in dkim_analysis:
                                html += f'''<div class="detail-item">
                                    <span class="detail-label">Selector:</span>
                                    <span class="detail-value"><code>{escape(str(dkim_analysis["Selector"]))}</code></span>
                                </div>'''
                            
                            # Canonicalization
                            if "Canonicalization" in dkim_analysis:
                                html += f'''<div class="detail-item">
                                    <span class="detail-label">Canonicalization:</span>
                                    <span class="detail-value">{escape(str(dkim_analysis["Canonicalization"]))}</span>
                                </div>'''
                            
                            # Validity
                            if "Validity" in dkim_analysis:
                                validity = dkim_analysis["Validity"]
                                validity_class = "success" if "valid" in str(validity).lower() else "danger"
                                validity_icon = "✅" if "valid" in str(validity).lower() else "❌"
                                html += f'''<div class="detail-item">
                                    <span class="detail-label">Signature Validity:</span>
                                    <span class="badge badge-{validity_class}">
                                        {validity_icon} {escape(str(validity)).replace('_', ' ').title()}
                                    </span>
                                </div>'''
                            
                            html += '</div>'  # Close dkim-details-grid
                            
                            # Headers Signed
                            if "Headers_Signed" in dkim_analysis and dkim_analysis["Headers_Signed"]:
                                html += '''<div class="signed-headers">
                                    <h6>📝 Signed Headers</h6>
                                    <div class="headers-list">'''
                                for header in dkim_analysis["Headers_Signed"]:
                                    html += f'<span class="header-tag">{escape(str(header))}</span>'
                                html += '</div></div>'
                            
                            # Body Hash Status
                            if "Body_Hash" in dkim_analysis:
                                body_hash_status = dkim_analysis["Body_Hash"]
                                hash_class = "success" if "present" in str(body_hash_status).lower() else "warning"
                                hash_icon = "✅" if "present" in str(body_hash_status).lower() else "⚠️"
                                html += f'''<div class="body-hash-status">
                                    <span class="detail-label">Body Hash:</span>
                                    <span class="badge badge-{hash_class}">
                                        {hash_icon} {escape(str(body_hash_status)).title()}
                                    </span>
                                </div>'''
                            
                            html += '</div>'  # Close dkim-details
                    else:
                        html += '''<div class="status-item danger">
                            <span class="status-icon">❌</span>
                            <span class="status-text">No DKIM Signature Found</span>
                        </div>
                        <div class="alert alert-warning">
                            <strong>⚠️ Security Risk:</strong> This email lacks DKIM authentication, making it more vulnerable to spoofing.
                        </div>'''
                    
                    html += '</div></div>'  # Close auth-status-box and dkim-analysis
                    
                    # SPF Analysis Section
                    spf_present = data_section.get("SPF_Present", False)
                    html += f'''<div class="spf-analysis">
                        <h5>📨 SPF (Sender Policy Framework) Analysis</h5>
                        <div class="auth-status-box">'''
                    
                    if spf_present:
                        html += '''<div class="status-item success">
                            <span class="status-icon">✅</span>
                            <span class="status-text">SPF Record Present</span>
                        </div>'''
                    else:
                        html += '''<div class="status-item danger">
                            <span class="status-icon">❌</span>
                            <span class="status-text">No SPF Record Found</span>
                        </div>
                        <div class="alert alert-warning">
                            <strong>⚠️ Security Risk:</strong> This domain lacks SPF configuration for email authentication.
                        </div>'''
                    
                    html += '</div></div>'  # Close auth-status-box and spf-analysis
                
                # Check if domain has DMARC record
                has_dmarc = dmarc_data.get("has_dmarc", False)
                dmarc_record = dmarc_data.get("dmarc_record")
                
                if has_dmarc and dmarc_record:
                    html += f'''<div class="dmarc-record">
                        <div class="dmarc-status success">
                            <h4>✅ DMARC Record Found</h4>
                        </div>
                        <div class="dmarc-details">
                            <strong>DMARC Record:</strong>
                            <div class="dmarc-record-text">
                                <code>{escape(str(dmarc_record))}</code>
                            </div>
                        </div>
                    </div>'''
                    
                    # Parse DMARC policy from record
                    if "p=" in str(dmarc_record):
                        policy_match = str(dmarc_record).split("p=")[1].split(";")[0] if "p=" in str(dmarc_record) else "none"
                        policy_icon = {"none": "⚠️", "quarantine": "📥", "reject": "🚫"}.get(policy_match, "❓")
                        policy_class = {"none": "warning", "quarantine": "info", "reject": "success"}.get(policy_match, "secondary")
                        
                        html += f'''<div class="dmarc-policy">
                            <h5>📋 DMARC Policy</h5>
                            <span class="badge badge-{policy_class}">
                                {policy_icon} Policy: {policy_match.upper()}
                            </span>
                        </div>'''
                else:
                    html += f'''<div class="dmarc-record">
                        <div class="dmarc-status danger">
                            <h4>❌ No DMARC Record Found</h4>
                        </div>
                        <div class="dmarc-warning">
                            <div class="alert alert-warning">
                                <strong>⚠️ Security Risk:</strong> This domain does not have a DMARC record configured. 
                                This makes it more vulnerable to email spoofing attacks.
                            </div>
                        </div>
                    </div>'''
                
                # Authentication results from headers
                if "authentication_results" in dmarc_data:
                    auth_results = dmarc_data["authentication_results"]
                    html += f'''<div class="auth-results">
                        <h5>🔍 Authentication Results</h5>
                        <div class="auth-details">'''
                    
                    for auth_type, result in auth_results.items():
                        result_class = "success" if "pass" in str(result).lower() else "danger" if "fail" in str(result).lower() else "warning"
                        result_icon = "✅" if "pass" in str(result).lower() else "❌" if "fail" in str(result).lower() else "⚠️"
                        
                        html += f'''<div class="auth-item">
                            <span class="auth-type">{escape(auth_type.upper())}:</span>
                            <span class="badge badge-{result_class}">
                                {result_icon} {escape(str(result))}
                            </span>
                        </div>'''
                    
                    html += '</div></div>'
                
                html += '</div>'  # Close dmarc-container
            else:
                html += '''<div class="alert alert-info">
                    <strong>🔐 No DMARC analysis data available</strong>
                </div>'''
            
            html += '</div>'  # Close section
        
        # Hashes section
        if "Hashes" in result and "Hashes" in result["Hashes"]:
            html += '<div class="section">'
            html += '<h3>File Hashes</h3>'
            hashes = result["Hashes"]["Hashes"]
            for hash_type, hash_value in hashes.items():
                formatted_hash = format_hash_value(hash_value)
                html += f'<div><strong>{escape(hash_type)}:</strong> {formatted_hash}</div>'
            html += '</div>'
        
        # Header Investigation section
        if "Headers" in result and "Investigation" in result["Headers"]:
            investigation = result["Headers"]["Investigation"]
            html += '<div class="section">'
            html += '<h3>🔍 Header Security Investigation</h3>'
            
            # Check if there's HTML formatted investigation data
            if "Headers" in result and "HTML_Investigation" in result["Headers"]:
                html_investigation = result["Headers"]["HTML_Investigation"]
                for key, value in html_investigation.items():
                    html += value
            else:
                # Fallback to basic investigation display
                # Sender IP investigation
                if "X-Sender-Ip" in investigation:
                    ip_info = investigation["X-Sender-Ip"]
                    safety_class = "success" if ip_info["Safety"] == "Safe" else "danger"
                    safety_icon = "✅" if ip_info["Safety"] == "Safe" else "🚨"
                    
                    html += f'''<div class="investigation-card">
                        <div class="investigation-header">
                            <h4>{safety_icon} Sender IP Analysis</h4>
                        </div>
                        <div class="investigation-content">
                            <div class="ip-details">
                                <strong>Safety Status:</strong> <span class="badge badge-{safety_class}">{ip_info["Safety"]}</span><br>
                                <strong>Positive Detections:</strong> {ip_info["Positives"]}
                            </div>
                            <div class="investigation-links">
                                <a href="{ip_info["Virustotal"]}" target="_blank" class="btn btn-outline-primary">
                                    🔍 VirusTotal Analysis
                                </a>
                                <a href="{ip_info["Abuseipdb"]}" target="_blank" class="btn btn-outline-secondary">
                                    📊 AbuseIPDB Check
                                </a>
                            </div>
                        </div>
                    </div>'''
                
                # Blacklist check
                if "Blacklist_Check" in investigation:
                    blacklist_info = investigation["Blacklist_Check"]
                    blacklist_status = blacklist_info.get("Blacklist_Status", "Unknown")
                    blacklist_icon = "✅" if "Not Blacklisted" in blacklist_status else "🚨"
                    blacklist_class = "success" if "Not Blacklisted" in blacklist_status else "danger"
                    
                    html += f'''<div class="investigation-card">
                        <div class="investigation-header">
                            <h4>{blacklist_icon} Blacklist Check</h4>
                        </div>
                        <div class="investigation-content">                            <div class="blacklist-details">
                                <strong>Status:</strong> <span class="badge badge-{blacklist_class}">{blacklist_status}</span>
                            </div>                        </div>
                    </div>'''
            
            html += '</div>'  # Close section
        
        html += '</div>'  # Close email-content
    
    html += """
        </div>
        <script>
        function showEmail(index) {
            console.log('Switching to email:', index);
            
            // Hide all email contents
            document.querySelectorAll('.email-content').forEach(el => {
                el.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(el => {
                el.classList.remove('active');
            });
            
            // Show selected email content
            const emailElement = document.getElementById(`email-${index}`);
            if (emailElement) {
                emailElement.classList.add('active');
                console.log('Showed email content for:', index);
            } else {
                console.error('Email element not found:', `email-${index}`);
            }
            
            // Add active class to selected tab
            const tabs = document.querySelectorAll('.tab');
            if (tabs[index]) {
                tabs[index].classList.add('active');
                console.log('Activated tab:', index);
            } else {
                console.error('Tab not found at index:', index);
            }
        }
        
        // Debug: Show current state on page load
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Page loaded');
            console.log('Email contents found:', document.querySelectorAll('.email-content').length);
            console.log('Tabs found:', document.querySelectorAll('.tab').length);
            console.log('Active email content:', document.querySelectorAll('.email-content.active').length);
        });
        </script>
    </body>
    </html>
    """
    
    return html

def save_html_from_json(json_file, output_file):
    """
    Generate HTML from JSON and save to file.
    
    Args:
        json_file: Path to the JSON input file
        output_file: Path to save the HTML output
    """
    html = generate_html_from_json(json_file)
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"HTML output saved to {output_file}")
    except Exception as e:
        print(f"Error saving HTML file: {e}")

if __name__ == "__main__":
    # Default paths for standalone execution
    json_file = "../../outputfile.json"
    output_file = "../../outputfile.html"
    
    # Check if the JSON file exists
    if os.path.exists(json_file):
        save_html_from_json(json_file, output_file)
    else:
        print(f"JSON file not found: {json_file}")
        print("Please provide the correct path to the JSON file.")

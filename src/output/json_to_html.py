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

def generate_headers_section(result):
    """Generate the headers section HTML for an email."""
    if "Headers" not in result or "Headers" not in result["Headers"]:
        return ""
    
    html_parts = []
    headers = result["Headers"]["Headers"]
    
    html_parts.append('            <div class="section">')
    html_parts.append('                <h3>📧 Email Headers</h3>')
    
    if "HTML_View" in headers:
        # Display formatted headers from header analyzer
        html_parts.append('                <div class="headers-container">')
        for key, value in headers["HTML_View"].items():
            if key == "Dettagli Tecnici":
                # Special handling for accordion-style technical details
                html_parts.append('                    <div class="header-section-expandable">')
                html_parts.append('                        <details>')
                html_parts.append(f'                            <summary>🔧 {escape(key)}</summary>')
                html_parts.append(f'                            <div class="expandable-content">{value}</div>')
                html_parts.append('                        </details>')
                html_parts.append('                    </div>')
            else:
                html_parts.append('                    <div class="header-item">')
                html_parts.append(f'                        <div class="header-label">{escape(key)}:</div>')
                html_parts.append(f'                        <div class="header-value">{value}</div>')
                html_parts.append('                    </div>')
        html_parts.append('                </div>')
    elif "Data" in headers:
        # Fallback to basic headers display
        html_parts.append('                <div class="headers-basic">')
        for key, value in headers["Data"].items():
            if key in ['subject', 'from', 'to', 'date', 'message-id']:
                html_parts.append(f'                    <div class="header-item"><strong>{escape(key.title())}:</strong> {escape(str(value))}</div>')
        html_parts.append('                </div>')
    
    html_parts.append('            </div>')
    return '\n'.join(html_parts)

def generate_links_section(result):
    """Generate the links section HTML for an email."""
    if "Links" not in result or "Links" not in result["Links"]:
        return ""
    
    html_parts = []
    links = result["Links"]["Links"]
    
    html_parts.append('            <div class="section">')
    html_parts.append('                <h3>🔗 Links Analysis</h3>')
    
    if links.get("unique_links"):
        html_parts.append(f'                <p>Found {links["total_links"]} unique links</p>')
        html_parts.append('                <div class="link-list">')
        for link in links["unique_links"]:
            safety_class = ""
            if "safety_score" in link:
                if link["safety_score"] >= 80:
                    safety_class = " safe-link"
                elif link["safety_score"] >= 50:
                    safety_class = " warning-link"
                else:
                    safety_class = " danger-link"
            html_parts.append(f'                    <div class="link-item{safety_class}">')            
            html_parts.append(f'                        <div class="link-url" style="display: block; width: 100%; padding-bottom: 10px;"><a href="{escape(link["url"])}" target="_blank">{escape(link["url"])}</a></div>')
            html_parts.append('                        <div style="clear: both; margin-top: 15px;"></div>') # Aggiungo spazio verticale e clear
            html_parts.append('                        <div class="link-details" style="display: block; margin-top: 8px;">')
            html_parts.append(f'                            <div class="domain-info">Domain: {escape(link["domain"])}</div>')
            if "safety_score" in link:
                html_parts.append(f'                            <div>Safety Score: {link["safety_score"]}%</div>')
            if link.get("threats"):
                html_parts.append(f'                            <div class="threats">Threats: {", ".join(escape(str(t)) for t in link["threats"])}</div>')
            if link.get("error"):
                html_parts.append(f'                            <div class="threats">Error: {escape(link["error"])}</div>')
            html_parts.append('                        </div>')
            html_parts.append('                    </div>')
        html_parts.append('                </div>')
    else:
        html_parts.append('                <p>No links found in this email</p>')
    
    html_parts.append('            </div>')
    return '\n'.join(html_parts)

def generate_attachments_section(result):
    """Generate the attachments section HTML for an email."""
    if "Attachments" not in result or "Attachments" not in result["Attachments"]:
        return ""
    
    html_parts = []
    attachments = result["Attachments"]["Attachments"]
    
    html_parts.append('            <div class="section">')
    html_parts.append('                <h3>📎 Attachments Analysis</h3>')
    
    # Check if there are attachments
    if "Allegati" in attachments and attachments["Allegati"]:
        # Warning message if present
        if "Avviso" in attachments:
            alert_class = "danger" if "ATTENZIONE" in attachments["Avviso"] else "info"
            html_parts.append(f'                <div class="alert alert-{alert_class}">')
            html_parts.append(f'                    <strong>⚠️ Warning:</strong> {escape(attachments["Avviso"])}')
            html_parts.append('                </div>')
        
        html_parts.append('                <div class="attachments-container">')
        
        for attachment_id, attachment in attachments["Allegati"].items():
            # Determine safety status
            is_suspicious = attachment.get("Sospetto", "No") == "Sì - File eseguibile (.exe/.bat)"
            safety_class = "danger" if is_suspicious else "success"
            safety_icon = "🚨" if is_suspicious else "✅"
            
            html_parts.append('                    <div class="attachment-card">')
            html_parts.append('                        <div class="attachment-header">')
            html_parts.append('                            <div class="attachment-name">')
            html_parts.append(f'                                {safety_icon} <strong>{escape(attachment.get("Filename", "Unknown"))}</strong>')
            html_parts.append('                            </div>')
            html_parts.append(f'                            <span class="badge badge-{safety_class}">')
            html_parts.append(f'                                {escape(attachment.get("Sospetto", "Unknown"))}')
            html_parts.append('                            </span>')
            html_parts.append('                        </div>')
            html_parts.append('                        <div class="attachment-details">')
            html_parts.append('                            <div class="attachment-info">')
            html_parts.append(f'                                <strong>Type:</strong> {escape(attachment.get("MIME Type", "Unknown"))}<br>')
            html_parts.append(f'                                <strong>Size:</strong> {escape(attachment.get("Size", "Unknown"))}<br>')
            html_parts.append(f'                                <strong>Email ID:</strong> {escape(str(attachment.get("Email ID", "Unknown")))}')
            html_parts.append('                            </div>')
            
            html_parts.append('                            <div class="hash-section">')
            html_parts.append('                                <details>')
            html_parts.append('                                    <summary>🔐 File Hashes</summary>')
            html_parts.append('                                    <div class="hash-content">')
            for hash_type in ["MD5", "SHA1", "SHA256"]:
                if hash_type in attachment:
                    hash_value = attachment[hash_type]
                    html_parts.append('                                        <div class="hash-item">')
                    html_parts.append(f'                                            <span class="hash-label">{hash_type}:</span>')
                    html_parts.append('                                            <code class="hash-value">')
                    html_parts.append(f'                                                <a href="https://www.virustotal.com/gui/file/{hash_value}" target="_blank" title="Check on VirusTotal">')
                    html_parts.append(f'                                                    {escape(hash_value)}')
                    html_parts.append('                                                </a>')
                    html_parts.append('                                            </code>')
                    html_parts.append('                                        </div>')
            html_parts.append('                                    </div>')
            html_parts.append('                                </details>')
            html_parts.append('                            </div>')
            
            # Add security analysis if available
            if "Stato Sicurezza" in attachment:
                security_safe = "Sicuro" in attachment["Stato Sicurezza"]
                security_class = "success" if security_safe else "danger"
                security_icon = "🛡️" if security_safe else "⚠️"
                
                html_parts.append('                            <div class="security-analysis">')
                html_parts.append(f'                                <h5>{security_icon} Security Analysis</h5>')
                html_parts.append(f'                                <span class="badge badge-{security_class}">')
                html_parts.append(f'                                    {escape(attachment["Stato Sicurezza"])}')
                html_parts.append('                                </span>')
                
                if "Dettagli Sicurezza" in attachment:
                    html_parts.append('                                <div class="security-details"><ul>')
                    for detail in attachment["Dettagli Sicurezza"]:
                        html_parts.append(f'                                    <li>{escape(detail)}</li>')
                    html_parts.append('                                </ul></div>')
                
                html_parts.append('                            </div>')
            
            # Add file path if available
            if "File Path" in attachment:
                file_path = attachment["File Path"]
                file_name = os.path.basename(file_path)
                html_parts.append('                            <div class="file-link">')
                html_parts.append('                                <strong>📁 Saved as:</strong>')
                html_parts.append(f'                                <a href="attachments/{escape(file_name)}" target="_blank">{escape(file_name)}</a>')
                html_parts.append('                            </div>')
            
            html_parts.append('                        </div>')  # Close attachment-details
            html_parts.append('                    </div>')      # Close attachment-card
        
        html_parts.append('                </div>')  # Close attachments-container
    else:
        html_parts.append('                <div class="alert alert-info">')
        html_parts.append('                    <strong>📎 No attachments found in this email</strong>')
        html_parts.append('                </div>')
    
    html_parts.append('            </div>')  # Close section
    return '\n'.join(html_parts)

def generate_dmarc_section(result):
    """Generate the DMARC section HTML for an email."""
    if "DMARC" not in result or "DMARC" not in result["DMARC"]:
        return ""
    
    html_parts = []
    dmarc_data = result["DMARC"]["DMARC"]
    
    html_parts.append('            <div class="section">')
    html_parts.append('                <h3>🔐 DMARC & DKIM Authentication Analysis</h3>')
    
    if dmarc_data:
        html_parts.append('                <div class="dmarc-container">')
        
        # Display domain information
        if "Data" in dmarc_data:
            data_section = dmarc_data["Data"]
            from_domain = data_section.get("From_Domain", "Unknown")
            
            html_parts.append('                    <div class="domain-info">')
            html_parts.append(f'                        <h4>📧 Domain Analysis: {escape(from_domain)}</h4>')
            html_parts.append('                    </div>')
            
            # DKIM Analysis Section
            dkim_present = data_section.get("DKIM_Present", False)
            html_parts.append('                    <div class="dkim-analysis">')
            html_parts.append('                        <h5>🔑 DKIM (DomainKeys Identified Mail) Analysis</h5>')
            html_parts.append('                        <div class="auth-status-box">')
            
            if dkim_present:
                html_parts.append('                            <div class="status-item success">')
                html_parts.append('                                <span class="status-icon">✅</span>')
                html_parts.append('                                <span class="status-text">DKIM Signature Present</span>')
                html_parts.append('                            </div>')
                
                # Display detailed DKIM analysis if available
                if "DKIM_Analysis" in data_section:
                    dkim_analysis = data_section["DKIM_Analysis"]
                    html_parts.append('                            <div class="dkim-details">')
                    html_parts.append('                                <h6>📋 DKIM Signature Details</h6>')
                    html_parts.append('                                <div class="dkim-details-grid">')
                    
                    # Version, Algorithm, Domain, Selector, Canonicalization
                    for field, label in [("Version", "Version"), ("Algorithm", "Algorithm"), 
                                       ("Domain", "Signing Domain"), ("Selector", "Selector"), 
                                       ("Canonicalization", "Canonicalization")]:
                        if field in dkim_analysis:
                            html_parts.append('                                    <div class="detail-item">')
                            html_parts.append(f'                                        <span class="detail-label">{label}:</span>')
                            if field in ["Algorithm", "Selector"]:
                                html_parts.append(f'                                        <span class="detail-value"><code>{escape(str(dkim_analysis[field]))}</code></span>')
                            elif field == "Domain":
                                html_parts.append(f'                                        <span class="detail-value"><strong>{escape(str(dkim_analysis[field]))}</strong></span>')
                            else:
                                html_parts.append(f'                                        <span class="detail-value">{escape(str(dkim_analysis[field]))}</span>')
                            html_parts.append('                                    </div>')
                    
                    html_parts.append('                                </div>')  # Close dkim-details-grid
                    html_parts.append('                            </div>')  # Close dkim-details
            else:
                html_parts.append('                            <div class="status-item danger">')
                html_parts.append('                                <span class="status-icon">❌</span>')
                html_parts.append('                                <span class="status-text">No DKIM Signature Found</span>')
                html_parts.append('                            </div>')
            
            html_parts.append('                        </div>')  # Close auth-status-box
            html_parts.append('                    </div>')      # Close dkim-analysis
        
        html_parts.append('                </div>')  # Close dmarc-container
    else:
        html_parts.append('                <div class="alert alert-info">')
        html_parts.append('                    <strong>🔐 No DMARC analysis data available</strong>')
        html_parts.append('                </div>')
    
    html_parts.append('            </div>')  # Close section
    return '\n'.join(html_parts)

def generate_hashes_section(result):
    """Generate the hashes section HTML for an email."""
    if "Hashes" not in result or "Hashes" not in result["Hashes"]:
        return ""
    
    html_parts = []
    hashes = result["Hashes"]["Hashes"]
    
    html_parts.append('            <div class="section">')
    html_parts.append('                <h3>🔐 File Hashes</h3>')
    
    for hash_type, hash_value in hashes.items():
        formatted_hash = format_hash_value(hash_value)
        html_parts.append(f'                <div><strong>{escape(hash_type)}:</strong> {formatted_hash}</div>')
    
    html_parts.append('            </div>')
    return '\n'.join(html_parts)

def generate_investigation_section(result):
    """Generate the header investigation section HTML for an email."""
    if "Headers" not in result or "Investigation" not in result["Headers"]:
        return ""
    
    html_parts = []
    investigation = result["Headers"]["Investigation"]
    
    html_parts.append('            <div class="section">')
    html_parts.append('                <h3>🔍 Header Security Investigation</h3>')
    
    # Check if there's HTML formatted investigation data
    if "Headers" in result and "HTML_Investigation" in result["Headers"]:
        html_investigation = result["Headers"]["HTML_Investigation"]
        for key, value in html_investigation.items():
            html_parts.append(f'                {value}')
    else:
        # Fallback to basic investigation display
        # Sender IP investigation
        if "X-Sender-Ip" in investigation:
            ip_info = investigation["X-Sender-Ip"]
            safety_class = "success" if ip_info["Safety"] == "Safe" else "danger"
            safety_icon = "✅" if ip_info["Safety"] == "Safe" else "🚨"
            
            html_parts.append('                <div class="investigation-card">')
            html_parts.append('                    <div class="investigation-header">')
            html_parts.append(f'                        <h4>{safety_icon} Sender IP Analysis</h4>')
            html_parts.append('                    </div>')
            html_parts.append('                    <div class="investigation-content">')
            html_parts.append('                        <div class="ip-details">')
            html_parts.append(f'                            <strong>Safety Status:</strong> <span class="badge badge-{safety_class}">{ip_info["Safety"]}</span><br>')
            html_parts.append(f'                            <strong>Positive Detections:</strong> {ip_info["Positives"]}')
            html_parts.append('                        </div>')
            html_parts.append('                    </div>')
            html_parts.append('                </div>')
    
    html_parts.append('            </div>')  # Close section
    return '\n'.join(html_parts)

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
        
    # Start building HTML with proper structure
    html_parts = []
    
    # HTML head and opening structure
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Analysis Results</title>
    {get_base_styles()}
</head>
<body>
    <div class="container">
        <h1>Email Analysis Results</h1>""")
    
    # Generate tabs for each email
    html_parts.append('        <div class="tab-container">')
    for i, result in enumerate(data):
        active = " active" if i == 0 else ""
        html_parts.append(f'            <button class="tab{active}" onclick="showEmail({i})">Email {i+1}</button>')
    html_parts.append('        </div>')
    
    # Generate content for each email
    for i, result in enumerate(data):
        active = " active" if i == 0 else ""
        html_parts.append(f'        <div id="email-{i}" class="email-content{active}">')        # Add headers section
        html_parts.append(generate_headers_section(result))
        
        # Add header investigation section
        html_parts.append(generate_investigation_section(result))
        
        # Add links section
        html_parts.append(generate_links_section(result))
        
        # Add DMARC section
        html_parts.append(generate_dmarc_section(result))
        
        # Add attachments section
        html_parts.append(generate_attachments_section(result))
        
        # Add hashes section
        html_parts.append(generate_hashes_section(result))
        
        html_parts.append('        </div>')  # Close email-content
    
    # Close container and add JavaScript
    html_parts.append("""        </div>
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
    </html>""")
    
    return '\n'.join(html_parts)

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

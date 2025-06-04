"""
Convert JSON analysis results to HTML.
"""

import json
from html import escape
import os
from .styles import get_base_styles

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
            <h1>Email Analysis Results</h1>
    """
    
    # Generate tabs for each email
    html += '<div class="tab-container">'
    for i, result in enumerate(data):
        active = " active" if i == 0 else ""
        html += f'<button class="tab{active}" onclick="showEmail({i})">Email {i+1}</button>'
    html += '</div>'
    
    # Generate content for each email
    for i, result in enumerate(data):
        active = " active" if i == 0 else ""
        html += f'<div id="email-{i}" class="email-content{active}">'
        
        # Headers section
        if "Headers" in result and "Headers" in result["Headers"]:
            headers = result["Headers"]["Headers"]
            html += '<div class="section">'
            html += '<h3>Headers</h3>'
            if "HTML_View" in headers:
                for key, value in headers["HTML_View"].items():
                    html += f'<div class="header-item"><strong>{escape(key)}:</strong> {value}</div>'
            html += '</div>'
        
        # Links section
        if "Links" in result and "Links" in result["Links"]:
            html += '<div class="section">'
            html += '<h3>Links Analysis</h3>'
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
        
        # Hashes section
        if "Hashes" in result and "Hashes" in result["Hashes"]:
            html += '<div class="section">'
            html += '<h3>File Hashes</h3>'
            hashes = result["Hashes"]["Hashes"]
            for hash_type, hash_value in hashes.items():
                formatted_hash = format_hash_value(hash_value)
                html += f'<div><strong>{escape(hash_type)}:</strong> {formatted_hash}</div>'
            html += '</div>'
        
        html += '</div>'  # Close email-content
    
    html += """
        </div>
        <script>
        function showEmail(index) {
            // Hide all email contents
            document.querySelectorAll('.email-content').forEach(el => {
                el.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(el => {
                el.classList.remove('active');
            });
            
            // Show selected email content
            document.getElementById(`email-${index}`).classList.add('active');
            
            // Add active class to selected tab
            document.querySelectorAll('.tab')[index].classList.add('active');
        }
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

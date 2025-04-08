"""
HTML output generation functionality.
"""

import os
from html_generator import generate_table_from_json
from datetime import datetime

def generate_html_output(analysis_results, output_filename):
    """
    Generate an HTML output file from analysis results.
    
    Args:
        analysis_results: List of analysis results for each email
        output_filename: Name of the output file
        
    Returns:
        Path to the output file
    """
    # Ensure the output directory exists
    output_dir = os.path.dirname(output_filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Format the results for HTML generation
    formatted_data = {
        "Information": {
            "Project": {
                "Name": "Email Analyzer",
                "Url": "https://github.com/keraattin/EmailAnalyzer",
                "Version": "1.0.0"
            },
            "Scan": {
                "Filename": os.path.basename(output_filename),
                "Generated": datetime.now().strftime("%B %d, %Y - %H:%M:%S")
            }
        },
        "Analysis": format_results_for_html(analysis_results[0] if analysis_results else {})
    }
    
    # Generate HTML content
    html_content = generate_table_from_json(formatted_data)
    
    # Write the results to the output file
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return output_filename

def format_results_for_html(result):
    """
    Format analysis results for HTML output.
    
    Args:
        result: Analysis result for a single email
        
    Returns:
        Formatted data for HTML generation
    """
    formatted = {}
    
    # Format headers data
    if "Headers" in result:
        formatted["Headers"] = result["Headers"]["Headers"]
    
    # Format links data
    if "Links" in result:
        formatted["Links"] = result["Links"]["Links"]
    
    # Format attachments data
    if "Attachments" in result:
        formatted["Attachments"] = result["Attachments"]["Attachments"]
    
    # Format hashes data
    if "Hashes" in result:
        formatted["Digests"] = result["Hashes"]["Hashes"]
    
    return formatted
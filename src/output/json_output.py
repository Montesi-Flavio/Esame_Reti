"""
JSON output generation functionality.
"""

import json
import os
from datetime import datetime

def generate_json_output(analysis_results, output_filename):
    """
    Generate a JSON output file from analysis results.
    
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
    
    # Write the results to the output file
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(analysis_results, f, ensure_ascii=False, indent=4)
    
    return output_filename

def format_analysis_result(email_file, headers_data, links_data, hashes_data, attachments_data=None):
    """
    Format analysis data for output.
    
    Args:
        email_file: Path to the email file
        headers_data: Header analysis data
        links_data: Link analysis data
        hashes_data: Hash analysis data
        attachments_data: Attachment analysis data
        
    Returns:
        Formatted analysis result dictionary
    """
    result = {
        "File": email_file,
        "Headers": {"Headers": headers_data},
        "Links": {"Links": links_data},
        "Hashes": {"Hashes": hashes_data}
    }
    
    # Add attachments data if available
    if attachments_data:
        result["Attachments"] = {"Attachments": attachments_data}
        
    return result
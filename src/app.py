"""
Main application entry point for Email Analyzer.
"""

import os
import sys
from argparse import ArgumentParser

# Import modules from restructured project
from config import (
    EMAIL_SERVER, EMAIL_USER, EMAIL_PASSWORD, DEFAULT_MAILBOX, 
    DEFAULT_OUTPUT_DIR, SUPPORTED_FILE_TYPES, SUPPORTED_OUTPUT_TYPES
)
from email_core import fetch_emails, get_email_content
from analyzers.header_analyzer import parse_email_headers
from analyzers.link_analyzer import analyze_links
from analyzers.hash_analyzer import calculate_hashes
from analyzers.attachment_analyzer import analyze_attachments
from output.json_output import generate_json_output, format_analysis_result
from output.html_output import generate_html_output

def parse_arguments():
    """Parse command line arguments."""
    parser = ArgumentParser(description="Email Analyzer")
    parser.add_argument("-s", "--server", default=EMAIL_SERVER, help="IMAP server")
    parser.add_argument("-u", "--user", default=EMAIL_USER, help="Email user")
    parser.add_argument("-p", "--password", default=EMAIL_PASSWORD, help="Email password")
    parser.add_argument("-m", "--mailbox", default=DEFAULT_MAILBOX, help="Mailbox to download emails from")
    parser.add_argument("-d", "--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory to save downloaded emails")
    parser.add_argument("-i", "--investigate", action="store_true", help="Enable investigation mode")
    parser.add_argument("-o", "--output", default="outputfile.json", help="Output file name (JSON or HTML)")
    parser.add_argument("-a", "--save-attachments", action="store_true", help="Save email attachments to disk")

    args = parser.parse_args()

    # Validate output file format
    if args.output and not any(args.output.endswith(ext) for ext in SUPPORTED_OUTPUT_TYPES):
        print("Error: Output file must be in JSON or HTML format.")
        sys.exit(1)

    return args

def analyze_emails(eml_files, investigate=False, save_attachments=False, output_dir=None):
    """
    Analyze multiple email files.
    
    Args:
        eml_files: List of email file paths
        investigate: Whether to perform security investigation
        save_attachments: Whether to save email attachments
        output_dir: Directory to save attachments
        
    Returns:
        List of analysis results
    """
    all_data = []

    for eml_file in eml_files:
        # Get email content
        mail_data = get_email_content(eml_file)
        
        # Analyze headers
        headers = parse_email_headers(mail_data.as_string(), investigate)
        
        # Calculate file hashes
        hashes = calculate_hashes(eml_file, investigate)
        
        # Analyze links
        links_data = analyze_links(mail_data.as_string(), investigate)
        
        # Analyze attachments
        attachments_data = analyze_attachments(eml_file, investigate, save_attachments, output_dir)

        # Format the result
        result = format_analysis_result(eml_file, headers, links_data, hashes, attachments_data)
        all_data.append(result)

    return all_data

def main():
    """Main application entry point."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Fetch emails from server
    eml_files = fetch_emails(
        args.server, args.user, args.password, 
        args.mailbox, args.output_dir
    )
    
    if not eml_files:
        print("No email files found or downloaded.")
        sys.exit(1)
    
    # Analyze the emails
    analysis_results = analyze_emails(eml_files, args.investigate, args.save_attachments, args.output_dir)
    
    # Generate output file based on extension
    if args.output.endswith('.html'):
        output_file = generate_html_output(analysis_results, args.output)
    else:
        output_file = generate_json_output(analysis_results, args.output)
        
    print(f"Analysis complete. Results saved to {output_file}")

if __name__ == "__main__":
    main()

"""
Configuration settings for the Email Analyzer application.
"""
import os

# API Keys
VIRUSTOTAL_API_KEY = "bd967895e71ce6eeb87d62f473b94fcc29e2afddf79d4d40b821e003ceef9b15"

# Email Settings
EMAIL_SERVER = "webmail.register.it"
EMAIL_USER = "test@maurimori.eu"
EMAIL_PASSWORD = "W2024pc!Q"
DEFAULT_MAILBOX = "INBOX"

# Application Settings
SUPPORTED_FILE_TYPES = ["eml"]
SUPPORTED_OUTPUT_TYPES = ["json", "html"]
DEFAULT_OUTPUT_DIR = "emails"

# Regular Expressions
LINK_REGEX = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
MAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

# Date Format
DATE_FORMAT = "%B %d, %Y - %H:%M:%S"

# DNS Blacklists
BLACKLISTS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]

# Cache Settings
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
CACHE_EXPIRY_DAYS = 7  # Cache expiry in days

# Additional Security Service API Keys (Optional)
# Set these as environment variables for enhanced security analysis

# URLScan.io - Free tier available with registration
URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY', '0197794c-7780-77dc-879f-5f0ef588b06c')

# AbuseIPDB - Enhanced features with API key
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'e280c07cb4fcaa941f9dcb1d246189f629230f0af54919b654b90c1a33a96eee4f1ca711489d1e2a')

# Security Analysis Configuration
SECURITY_ANALYSIS_CONFIG = {
    'enable_multiple_services': True,  # Use multiple services for comprehensive analysis
    'virustotal_enabled': True,        # Always enabled as primary service
    'urlscan_enabled': True,           # Free service, no API key required
    'phishtank_enabled': True,         # Free service
    'malwarebazaar_enabled': True,     # Free service
    'abuseipdb_enhanced': bool(ABUSEIPDB_API_KEY)  # Enhanced features with API key
}

# Threat Intelligence Sources
THREAT_INTEL_SOURCES = {
    'virustotal': 'https://www.virustotal.com/gui/search/',
    'urlscan': 'https://urlscan.io/search/#',
    'abuseipdb': 'https://www.abuseipdb.com/check/',
    'phishtank': 'https://www.phishtank.com/',
    'malwarebazaar': 'https://bazaar.abuse.ch/browse/',
    'urlvoid': 'https://www.urlvoid.com/scan/'
}
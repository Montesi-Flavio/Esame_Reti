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
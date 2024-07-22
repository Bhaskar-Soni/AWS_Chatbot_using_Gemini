import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Base directory of the project

# Paths for different resources
CREDENTIALS_FILE = os.path.join(BASE_DIR, 'credentials')
ENCRYPTION_KEY_FILE = os.path.join(BASE_DIR, 'encryption_key.key')
AWS_AUDIT_REPORT_DIR = os.path.join(BASE_DIR, 'AWS-Audit-Report')
PEM_FILE_PATH = os.path.join(BASE_DIR, 'ec2-key.pem')
SCOUT_SCRIPT_PATH = os.path.join(BASE_DIR, 'Audit', 'Scout2.py')

# Gemini API configurations
GEMINI_API_KEY = 'GEMINI_API_KEY'
GEMINI_API_ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent'
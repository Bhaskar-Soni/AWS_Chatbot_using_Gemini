import streamlit as st

st.set_page_config(page_title="Audit Report")

import subprocess
from pathlib import Path
import shutil
import os
import webbrowser
from cryptography.fernet import Fernet
from menu import custom_menu
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE, SCOUT_SCRIPT_PATH

# Display the custom menu
custom_menu()

# Function to load encryption key
def load_key():
    with open(ENCRYPTION_KEY_FILE, 'rb') as f:
        return f.read()

# Initialize Fernet cipher suite with loaded encryption key
key = load_key()
cipher_suite = Fernet(key)

# Function to decrypt data
def decrypt_data(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
    return decrypted_data.decode()

# Function to load credentials from file and decrypt them
def load_credentials():
    with open(CREDENTIALS_FILE, 'r') as f:
        lines = f.readlines()
        access_key = decrypt_data(lines[0].split(': ')[1].strip())
        secret_key = decrypt_data(lines[1].split(': ')[1].strip())
        region = lines[2].split(': ')[1].strip()
        return access_key, secret_key, region

# Function to run Scout2 and generate a report
def run_scout2(aws_access_key_id, aws_secret_access_key, aws_session_token, aws_region):
    report_dir = Path("AWS-Audit-Report")

    # Remove previous report directory if it exists
    if report_dir.exists():
        shutil.rmtree(report_dir)

    # Path to the Scout2.py script
    scout2_script_path = SCOUT_SCRIPT_PATH

    # Set environment variables for AWS credentials
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = aws_access_key_id
    env["AWS_SECRET_ACCESS_KEY"] = aws_secret_access_key
    if aws_session_token:
        env["AWS_SESSION_TOKEN"] = aws_session_token

    # Running Scout2 using subprocess
    result = subprocess.run([
        "python3", scout2_script_path,
        "--regions", aws_region,
        "--report-dir", str(report_dir)
    ], capture_output=True, text=True, env=env)

    if result.returncode != 0:
        raise Exception(f"AWS Audit failed with error: {result.stderr}")

    return report_dir

# Streamlit app setup
st.title("AWS Audit Report")

# Function to check if report exists
def report_exists(report_dir):
    report_path = report_dir / "report.html"
    return report_path.is_file()

# Check if previous report exists
report_dir = Path("AWS-Audit-Report")
show_previous_report_button = report_exists(report_dir)

# Load AWS credentials
aws_access_key_id, aws_secret_access_key, aws_region = load_credentials()

# Form to input AWS session token
with st.form("aws_session_token_form"):
    aws_session_token = st.text_input("AWS Session Token (Optional)", type="password")
    submit_button = st.form_submit_button(label="Generate Now")

# When the user submits the form
if submit_button:
    # Hide the "View Previous Audit Report" button
    show_previous_report_button = False
    
    # Run Scout2 and generate the report
    with st.spinner("Generating Report..."):
        try:
            report_dir = run_scout2(aws_access_key_id, aws_secret_access_key, aws_session_token, aws_region)
            st.success("AWS Audit report generated successfully!")
            st.write(f"You can view the report in the '{report_dir}' directory.")
            
            # Check if new report exists and show "View Audit Report" button
            if report_exists(report_dir):
                if st.button("View Audit Report", key="view_current_report"):
                    file_path = report_dir / "report.html"
                    webbrowser.open_new_tab(file_path.resolve().as_uri())

        except Exception as e:
            st.error(f"Failed to generate AWS Audit report: {e}")

# Display "View Previous Audit Report" button if it exists and was not hidden by submit action
if show_previous_report_button:
    if st.button("View Previous Audit Report", key="view_previous_report"):
        file_path = report_dir / "report.html"
        webbrowser.open_new_tab(file_path.resolve().as_uri())


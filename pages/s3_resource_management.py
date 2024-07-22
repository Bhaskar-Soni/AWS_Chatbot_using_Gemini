import streamlit as st

st.set_page_config(page_title="S3 Resource Management")

import boto3
import time
from cryptography.fernet import Fernet
from menu import custom_menu  # Import the custom menu function
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE
import pages.s3_vulnerability_checker as s3_vuln_checker  # Import the S3 vulnerability checker module

# Display the custom menu
custom_menu()

st.title("S3 Resource Management")

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

# Load and decrypt credentials
aws_access_key_id, aws_secret_access_key, region = load_credentials()

def create_s3_bucket(bucket_name, region):
    try:
        s3_client = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region)
        if region == "us-east-1":
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})
        st.success(f"S3 bucket '{bucket_name}' created successfully in region '{region}'.")

        # Display redirecting message with countdown
        countdown_text = st.empty()
        for i in range(10, 0, -1):
            countdown_text.write(f"Redirecting to the chatbot in {i} seconds...")
            time.sleep(1)
        st.write("Redirecting to the Chatbot...")
        st.switch_page("pages/chatbot.py")

    except Exception as e:
        error_msg = str(e)
        if "IllegalLocationConstraintException" in error_msg:
            st.error(f"The {region} location constraint is incompatible for the region-specific endpoint this request was sent to.")
        elif "BucketAlreadyExists" in error_msg:
            st.error(f"Bucket '{bucket_name}' already exists. Please choose a different bucket name.")
        else:
            st.error(f"Error occurred: {error_msg}")

def list_s3_buckets():
    try:
        s3_client = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        response = s3_client.list_buckets()
        buckets = response['Buckets']
        return buckets
    except Exception as e:
        st.error(f"Error listing S3 buckets: {e}")
        return []

def main():
    task = st.selectbox("What would you like to do today?", ["Create S3 Bucket", "List S3 Buckets", "Run S3 Vulnerability Checker"])

    if task == "Create S3 Bucket":
        st.subheader("Create S3 Bucket")
        with st.form("s3_bucket_form"):
            bucket_name = st.text_input("Bucket Name")
            region = st.selectbox("Region", ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"])

            col1, col_spacer, col2 = st.columns([1, 2, 1])
            with col1:
                submit_button = st.form_submit_button("Create S3 Bucket")
            with col2:
                return_button = st.form_submit_button("↩️")

        # Handle S3 bucket form submission
        if submit_button:
            if bucket_name and region:
                create_s3_bucket(bucket_name, region)
            else:
                st.error("Please fill in all fields.")

        # Handle return button click
        if return_button:
            st.write("Redirecting to the previous page...")
            st.switch_page("pages/chatbot.py")

    elif task == "List S3 Buckets":
        st.subheader("List S3 Buckets")
        buckets = list_s3_buckets()
        if buckets:
            st.write("Existing S3 Buckets:")
            for bucket in buckets:
                st.write(f"- {bucket['Name']}")
        else:
            st.write("No S3 buckets found.")

    elif task == "Run S3 Vulnerability Checker":
        st.subheader("S3 Vulnerability Checker")
        s3_vuln_checker.s3_vuln_checker()

if __name__ == "__main__":
    main()

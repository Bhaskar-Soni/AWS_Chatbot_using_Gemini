import streamlit as st

st.set_page_config(page_title="AWS Credentials")

import boto3
from cryptography.fernet import Fernet
import os
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE

# Function to generate or load encryption key
def get_or_generate_key():
    key_file = ENCRYPTION_KEY_FILE  # Path to store the encryption key file

    # Check if encryption key file exists
    if os.path.exists(key_file):
        # Read the key from file
        with open(key_file, 'rb') as f:
            key = f.read()
    else:
        # Generate a new key and save it to file
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)

    return key

# Get or generate the encryption key
key = get_or_generate_key()
cipher_suite = Fernet(key)

# Function to encrypt data
def encrypt_data(data):
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data.decode()

# Function to store encrypted credentials
def store_credentials(access_key, secret_key, region):
    with open(CREDENTIALS_FILE, 'w') as f:
        f.write(f"Access Key ID: {encrypt_data(access_key)}\n")
        f.write(f"Secret Access Key: {encrypt_data(secret_key)}\n")
        f.write(f"AWS Region: {region}\n")

# Function to validate AWS credentials
def validate_aws_credentials(access_key, secret_key, region):
    try:
        client = boto3.client(
            'sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        response = client.get_caller_identity()

        st.success("Valid AWS credentials.")
        return True

    except Exception as e:
        st.error(f"Error validating AWS credentials: {e}")
        return False

# Main function to get user input, validate credentials, and store them
def main():
    st.title("AWS Credential Setup") 

    access_key = st.text_input("AWS Access Key ID:")
    secret_key = st.text_input("AWS Secret Access Key:", type="password")
    region = st.selectbox("AWS Region:", options=['us-east-1', 'us-west-1', 'us-west-2'])

    submit_button = st.button("Submit")

    if submit_button and access_key and secret_key and region:
        if validate_aws_credentials(access_key, secret_key, region):
            store_credentials(access_key, secret_key, region)
            st.switch_page("./pages/dashboard.py")
            st.markdown("---")
            st.markdown("Redirecting to dashboard...")
            st.experimental_rerun()

if __name__ == "__main__":
    main()


# pages/iam_users.py
import streamlit as st
import boto3
import pandas as pd
from cryptography.fernet import Fernet
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE

# Function to load encryption key
def load_key():
    with open(ENCRYPTION_KEY_FILE, 'rb') as f:
        return f.read()

# Function to decrypt data
def decrypt_data(encrypted_data, cipher_suite):
    decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
    return decrypted_data.decode()

# Function to load credentials from file and decrypt them
def load_credentials():
    key = load_key()
    cipher_suite = Fernet(key)

    with open(CREDENTIALS_FILE, 'r') as f:
        lines = f.readlines()
        access_key = decrypt_data(lines[0].split(': ')[1].strip(), cipher_suite)
        secret_key = decrypt_data(lines[1].split(': ')[1].strip(), cipher_suite)
        return access_key, secret_key

# Function to display IAM users using Streamlit
def display_iam_users():
    st.title("AWS IAM Users")

    try:
        # Load AWS credentials securely
        aws_access_key_id, aws_secret_access_key = load_credentials()

        # Initialize boto3 client with loaded credentials
        client = boto3.client(
            'iam',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name='us-east-1'
        )

        # Call IAM API to list users
        response = client.list_users()

        # Extract user information
        users = response['Users']
        user_data = [{"UserName": user['UserName'], "UserId": user['UserId'], "CreateDate": user['CreateDate']} for user in users]

        # Create a DataFrame for the users
        if user_data:
            df = pd.DataFrame(user_data)
            st.dataframe(df)
        else:
            st.info("No IAM users found in the account.")

    except Exception as e:
        st.error(f"Error retrieving IAM users: {e}")

# Export the display_iam_users function for import in other modules
__all__ = ['display_iam_users']

# If this script is run directly, execute the display_iam_users function
if __name__ == "__main__":
    display_iam_users()


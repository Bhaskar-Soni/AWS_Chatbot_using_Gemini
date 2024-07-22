import streamlit as st
import boto3
from cryptography.fernet import Fernet
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE

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

# Function to load encrypted AWS credentials and decrypt them
def load_aws_credentials():
    with open(CREDENTIALS_FILE, 'r') as f:
        lines = f.readlines()
        access_key = decrypt_data(lines[0].split(': ')[1].strip())
        secret_key = decrypt_data(lines[1].split(': ')[1].strip())
        return access_key, secret_key

# Function to check AWS Free Tier status
def check_free_tier():
    st.title("AWS Free Tier Checker")

    try:
        # Load and decrypt AWS credentials
        access_key_id, secret_access_key = load_aws_credentials()

        # Check if AWS credentials are provided
        if access_key_id and secret_access_key:
            # Create a new session using provided credentials
            session = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key
            )

            # Get AWS pricing client
            pricing_client = session.client('pricing', region_name='us-east-1')

            # Check if account is in Free Tier
            response = pricing_client.get_products(
                ServiceCode='AmazonEC2',
                Filters=[
                    {
                        'Type': 'TERM_MATCH',
                        'Field': 'usagetype',
                        'Value': 'BoxUsage:t2.micro'
                    }
                ]
            )

            # Check if there are any free tier products
            free_tier_available = len(response['PriceList']) > 0

            # Display result
            if free_tier_available:
                st.write("Your AWS account is enrolled in the Free Tier!")
            else:
                st.write("Your AWS account is not enrolled in the Free Tier.")

        else:
            st.write("AWS credentials could not be loaded.")
    except Exception as e:
        st.error(f"Error: {e}")

# Export the check_free_tier function for import in other modules
__all__ = ['check_free_tier']

# If this script is run directly, execute the check_free_tier function
if __name__ == "__main__":
    check_free_tier()


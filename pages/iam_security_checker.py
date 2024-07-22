import streamlit as st
import boto3
from datetime import datetime, timedelta
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

# Function to load credentials from file and decrypt them
def load_credentials():
    with open(CREDENTIALS_FILE, 'r') as f:
        lines = f.readlines()
        access_key = decrypt_data(lines[0].split(': ')[1].strip())
        secret_key = decrypt_data(lines[1].split(': ')[1].strip())
        region = lines[2].split(': ')[1].strip()
        return access_key, secret_key, region

# Function to initialize IAM client
def initialize_iam_client(aws_access_key_id, aws_secret_access_key, region_name):
    return boto3.client('iam', aws_access_key_id=aws_access_key_id, 
                        aws_secret_access_key=aws_secret_access_key, 
                        region_name=region_name)

# Check for unused IAM users and access keys
def check_unused_users_and_keys(iam_client):
    st.subheader("Unused IAM Users and Access Keys")
    try:
        # Get list of IAM users
        response = iam_client.list_users()
        users = response['Users']

        for user in users:
            username = user['UserName']
            user_creation_date = user['CreateDate']
            access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            if not access_keys:
                st.write(f"IAM User: {username} (Created on: {user_creation_date}) - No access keys found")

            for access_key in access_keys:
                access_key_id = access_key['AccessKeyId']
                access_key_creation_date = access_key['CreateDate']
                last_used = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                if 'LastUsedDate' not in last_used:
                    st.write(f"IAM User: {username} (Created on: {user_creation_date}) - Unused Access Key: {access_key_id} (Created on: {access_key_creation_date})")

    except Exception as e:
        st.error(f"Error checking for unused IAM users and access keys: {str(e)}")

# Check for unused IAM roles and policies
def check_unused_roles_and_policies(iam_client):
    st.subheader("Unused IAM Roles and Policies")
    try:
        # Get list of IAM roles
        response = iam_client.list_roles()
        roles = response['Roles']

        for role in roles:
            role_name = role['RoleName']
            role_creation_date = role['CreateDate']
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            if not attached_policies:
                st.write(f"IAM Role: {role_name} (Created on: {role_creation_date}) - No attached policies found")

    except Exception as e:
        st.error(f"Error checking for unused IAM roles and policies: {str(e)}")

# Check for excessive permissions
def check_excessive_permissions(iam_client):
    st.subheader("Excessive Permissions")
    try:
        # Get list of IAM users
        response = iam_client.list_users()
        users = response['Users']

        for user in users:
            username = user['UserName']
            attached_policies = iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies']
            if attached_policies:
                for policy in attached_policies:
                    st.write(f"IAM User: {username} - Attached Policy: {policy['PolicyName']}")

    except Exception as e:
        st.error(f"Error checking for excessive permissions: {str(e)}")

# Check for unauthorized access
def check_unauthorized_access(iam_client):
    st.subheader("Unauthorized Access")
    try:
        # Get list of IAM users
        response = iam_client.list_users()
        users = response['Users']

        for user in users:
            username = user['UserName']
            inline_policies = iam_client.list_user_policies(UserName=username)['PolicyNames']
            if inline_policies:
                for policy_name in inline_policies:
                    policy = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
                    policy_document = policy['PolicyDocument']
                    if '*' in policy_document.values():
                        st.write(f"IAM User: {username} - Unauthorized Policy: {policy_name}")

    except Exception as e:
        st.error(f"Error checking for unauthorized access: {str(e)}")

# Check for privilege escalation
def check_privilege_escalation(iam_client):
    st.subheader("Privilege Escalation")
    try:
        # Get list of IAM users
        response = iam_client.list_users()
        users = response['Users']

        for user in users:
            username = user['UserName']
            attached_policies = iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies']
            if attached_policies:
                for policy in attached_policies:
                    policy_document = iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                    if 'iam:*' in policy_document or 'sts:*' in policy_document:
                        st.write(f"IAM User: {username} - Privilege Escalation Policy: {policy['PolicyName']}")

    except Exception as e:
        st.error(f"Error checking for privilege escalation: {str(e)}")

# Check MFA settings
def check_mfa_settings(iam_client):
    st.subheader("MFA Settings")
    try:
        # Get list of IAM users
        response = iam_client.list_users()
        users = response['Users']

        for user in users:
            username = user['UserName']
            mfa_devices = iam_client.list_mfa_devices(UserName=username)['MFADevices']
            if not mfa_devices:
                st.write(f"IAM User: {username} - MFA not enabled")

    except Exception as e:
        st.error(f"Error checking MFA settings: {str(e)}")

# Check IAM password policy
def check_password_policy(iam_client):
    st.subheader("IAM Password Policy")
    try:
        # Get IAM password policy
        password_policy = iam_client.get_account_password_policy()
        st.write(password_policy)
    except Exception as e:
        st.error(f"Error checking IAM password policy: {str(e)}")

# Check access key rotation
def check_access_key_rotation(iam_client):
    st.subheader("Access Key Rotation")
    try:
        # Get list of IAM users
        response = iam_client.list_users()
        users = response['Users']

        for user in users:
            username = user['UserName']
            access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            if access_keys:
                for access_key in access_keys:
                    access_key_id = access_key['AccessKeyId']
                    create_date = access_key['CreateDate']
                    last_used = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                    if 'LastUsedDate' in last_used:
                        last_used_date = last_used['LastUsedDate'].replace(tzinfo=None)
                        if datetime.now() - last_used_date > timedelta(days=90):
                            st.write(f"IAM User: {username} - Access Key: {access_key_id} (Created on: {create_date}) - Not rotated for more than 90 days")
                    else:
                        st.write(f"IAM User: {username} - Access Key: {access_key_id} (Created on: {create_date}) - Never used")

    except Exception as e:
        st.error(f"Error checking access key rotation: {str(e)}")

# Main function
def iam_checker():
    # AWS credentials setup
    aws_access_key_id, aws_secret_access_key, region = load_credentials()

    # AWS region selection
    #region_name = st.selectbox("Select AWS Region", ["us-east-1", "us-west-2", "eu-west-1"])

    # AWS region selection
    selected_region = st.selectbox("Select AWS Region", ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'sa-east-1'], index=0)

    if st.button("Scan IAM"):
        try:
            # Initialize IAM client
            iam_client = initialize_iam_client(aws_access_key_id, aws_secret_access_key, selected_region)

            # Check various configurations
            check_unused_users_and_keys(iam_client)
            check_unused_roles_and_policies(iam_client)
            check_excessive_permissions(iam_client)
            check_unauthorized_access(iam_client)
            check_privilege_escalation(iam_client)
            check_mfa_settings(iam_client)
            check_password_policy(iam_client)
            check_access_key_rotation(iam_client)

        except Exception as e:
            st.error(f"An error occurred: {str(e)}")

    #return_button = st.button("Return to Chatbot")
    #if return_button:
    #    st.write("Redirecting to the previous page...")
    #    #st.experimental_rerun()
    #    st.switch_page("pages/chatbot.py")
import streamlit as st

st.set_page_config(page_title="IAM Resource Management")

import boto3
from cryptography.fernet import Fernet
from menu import custom_menu  # Import the custom menu function
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE
import pages.iam_security_checker as iam_checker

# Display the custom menu
custom_menu()

st.title("IAM Resource Management")

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

# Function to get policy ARN
def get_policy_arn(policy_name):
    try:
        iam_client = boto3.client('iam',
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key,
                                  region_name=region)

        response = iam_client.list_policies(
            Scope='AWS',
            OnlyAttached=False
        )

        for policy in response['Policies']:
            if policy['PolicyName'] == policy_name:
                return policy['Arn']

        return None
    except Exception as e:
        return str(e)

# Function to create IAM user
def create_iam_user(user_name, policy_names):
    try:
        iam_client = boto3.client('iam',
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key,
                                  region_name=region)

        response = iam_client.create_user(
            UserName=user_name
        )

        if policy_names:
            for policy_name in policy_names:
                policy_arn = get_policy_arn(policy_name)
                if policy_arn:
                    iam_client.attach_user_policy(
                        UserName=user_name,
                        PolicyArn=policy_arn
                    )
                else:
                    st.warning(f"Policy '{policy_name}' not found.")

        return response
    except Exception as e:
        return str(e)

# Function to list IAM users
def list_iam_users():
    try:
        iam_client = boto3.client('iam',
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key,
                                  region_name=region)

        users = iam_client.list_users()['Users']
        user_details = []

        for user in users:
            user_name = user['UserName']
            creation_date = user['CreateDate']

            # Get groups for the user
            groups_response = iam_client.list_groups_for_user(UserName=user_name)
            group_names = [group['GroupName'] for group in groups_response['Groups']]

            # Get policies for the user
            policies_response = iam_client.list_attached_user_policies(UserName=user_name)
            policy_names = [policy['PolicyName'] for policy in policies_response['AttachedPolicies']]

            user_details.append({
                'UserName': user_name,
                'CreateDate': creation_date,
                'Groups': group_names,
                'Policies': policy_names
            })

        return user_details
    except Exception as e:
        return str(e)

# Function to delete IAM user
def delete_iam_user(user_name):
    try:
        iam_client = boto3.client('iam',
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key,
                                  region_name=region)

        response = iam_client.delete_user(
            UserName=user_name
        )
        return response
    except Exception as e:
        return str(e)

# Main menu for user to select action
task = st.selectbox("Select a task", ["Create IAM User", "List IAM Users", "Delete IAM User", "Run IAM Vulnerability Checker"])

# Display form based on selected task
if task == "Create IAM User":
    st.header("Create IAM User")
    with st.form("create_iam_user_form"):
        user_name = st.text_input("User Name")
        policy_names = st.text_area("Policy Names (comma-separated)", help="Enter the names of the policies you want to attach to the user")
        policy_names = [policy_name.strip() for policy_name in policy_names.split(',') if policy_name.strip()]

        submit_button = st.form_submit_button("Create IAM User")

    if submit_button:
        if not user_name:
            st.warning("Please fill in all required fields.")
        else:
            response = create_iam_user(user_name, policy_names)
            if isinstance(response, dict) and 'User' in response:
                st.success("IAM user created successfully!")
                st.write("IAM User Name:", response['User']['UserName'])
            else:
                st.error("Error creating IAM user:")
                st.error(response)

elif task == "List IAM Users":
    st.header("List IAM Users")
    users = list_iam_users()
    if isinstance(users, list):
        st.write("IAM Users:")
        for user in users:
            st.write(f"User Name: {user['UserName']}")
            st.write(f"Creation Date: {user['CreateDate']}")
            st.write(f"Groups: {', '.join(user['Groups']) if user['Groups'] else 'No groups assigned'}")
            st.write(f"Policies: {', '.join(user['Policies']) if user['Policies'] else 'No policies attached'}")
            st.write("---")
    else:
        st.error("Error listing IAM users:")
        st.error(users)

elif task == "Delete IAM User":
    st.header("Delete IAM User")
    with st.form("delete_iam_user_form"):
        user_name = st.text_input("User Name")
        submit_button = st.form_submit_button("Delete IAM User")

    if submit_button:
        if not user_name:
            st.warning("Please fill in the user name.")
        else:
            response = delete_iam_user(user_name)
            if response == {}:
                st.success("IAM user deleted successfully!")
            else:
                st.error("Error deleting IAM user:")
                st.error(response)

elif task == "Run IAM Vulnerability Checker":
    st.subheader("IAM Vulnerability Checker")
    iam_checker.iam_checker()

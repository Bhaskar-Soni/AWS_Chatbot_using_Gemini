import streamlit as st

st.set_page_config(page_title="RDS Resource Management")

import boto3
import re
from cryptography.fernet import Fernet
from menu import custom_menu  # Import the custom menu function
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE
import pages.rds_vulnerability_scanner as run_scanner

# Display the custom menu
custom_menu()

st.title("AWS RDS Management")

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
aws_access_key_id, aws_secret_access_key, default_region = load_credentials()

# AWS RDS client initialization
rds_client = boto3.client('rds', 
                          aws_access_key_id=aws_access_key_id,
                          aws_secret_access_key=aws_secret_access_key,
                          region_name=default_region)

# Function to list existing RDS instances
def list_rds_instances():
    try:
        response = rds_client.describe_db_instances()
        return response['DBInstances']
    except Exception as e:
        st.error(f"Error listing RDS instances: {str(e)}")
        return []

# Function to create an RDS instance
def create_rds_instance(params):
    try:
        response = rds_client.create_db_instance(
            DBInstanceIdentifier=params['db_instance_identifier'],
            DBInstanceClass=params['db_instance_class'],
            Engine=params['engine'],
            EngineVersion=params['engine_version'],
            MasterUsername=params['master_username'],
            MasterUserPassword=params['master_password'],
            AllocatedStorage=20,
            StorageType='gp2',
            PubliclyAccessible=True,
            Tags=[{'Key': 'Name', 'Value': 'MyDB'}],
        )
        return response
    except Exception as e:
        return str(e)

# Function to start an existing RDS instance
def start_rds_instance(db_instance_identifier):
    try:
        response = rds_client.start_db_instance(DBInstanceIdentifier=db_instance_identifier)
        return response
    except Exception as e:
        return str(e)

# Function to stop an existing RDS instance
def stop_rds_instance(db_instance_identifier):
    try:
        response = rds_client.stop_db_instance(DBInstanceIdentifier=db_instance_identifier)
        return response
    except Exception as e:
        return str(e)

# Function to delete an existing RDS instance
def delete_rds_instance(db_instance_identifier):
    try:
        response = rds_client.delete_db_instance(
            DBInstanceIdentifier=db_instance_identifier,
            SkipFinalSnapshot=True  # Modify as per your snapshot policy
        )
        return response
    except Exception as e:
        return str(e)

# Function to validate password
def validate_password(password):
    if len(password) < 8 or len(password) > 41:
        return False
    if not re.match(r'^[ -~]+$', password):
        return False
    forbidden_chars = ['/', '@', '"', ' ']
    if any(char in password for char in forbidden_chars):
        return False
    return True

# Main function
def main():
    task = st.selectbox("What would you like to do today?", ["Create RDS Instance", "List RDS Instances", "Manage RDS Instances", "Run RDS Vulnerability Checker"])

    if task == "Create RDS Instance":
        st.subheader("Create RDS Instance")
        with st.form("rds_instance_form"):
            db_instance_identifier = st.text_input("DB Instance Identifier")
            engine = st.selectbox("Database Engine", ["Aurora (MySQL Compatible)", "Aurora (PostgreSQL Compatible)", "MySQL", "MariaDB", "PostgreSQL", "Oracle", "Microsoft SQL Server", "IBM Db2"])
            engine_version = st.text_input("Database Engine Version (e.g., 5.7, 8.0)")
            db_instance_class = st.text_input("DB Instance Class (e.g., db.t2.micro)")

            st.write("Password Policy:")
            st.write("- Minimum length: 8 characters")
            st.write("- Maximum length: 41 characters")
            st.write("- Exclude using these: '/', '@', '\"', ' ')")

            master_username = st.text_input("Master Username")
            master_password = st.text_input("Master Password", type="password", help="Make sure your password meets RDS requirements")

            col1, col_spacer, col2 = st.columns([1, 2, 1])
            with col1:
                submit_button = st.form_submit_button("Create RDS Instance")
            with col2:
                return_button = st.form_submit_button("↩")

        if submit_button:
            if not db_instance_identifier or not master_username or not master_password:
                st.warning("Please fill in all required fields.")
            elif not validate_password(master_password):
                st.warning("Invalid password. Please ensure it meets the password policy.")
            else:
                params = {
                    'db_instance_identifier': db_instance_identifier,
                    'db_instance_class': db_instance_class,
                    'engine': engine,
                    'engine_version': engine_version,
                    'master_username': master_username,
                    'master_password': master_password
                }
                response = create_rds_instance(params)
                if isinstance(response, str):
                    st.error("Error creating RDS instance:")
                    st.error(response)
                else:
                    st.success("RDS instance created successfully!")
                    if 'DBInstance' in response and 'Endpoint' in response['DBInstance']:
                        endpoint = response['DBInstance']['Endpoint']
                        st.write("Endpoint:", endpoint)
                    else:
                        st.warning("Endpoint information not available.")
        
    elif task == "List RDS Instances":
        st.subheader("List RDS Instances")
        instances = list_rds_instances()
        if instances:
            for instance in instances:
                st.write(f"- {instance['DBInstanceIdentifier']} ({instance['DBInstanceClass']}, {instance['Engine']}, {instance['DBInstanceStatus']})")
        else:
            st.write("No RDS instances found.")

    elif task == "Manage RDS Instances":
        st.subheader("Manage RDS Instances")
        action = st.selectbox("Select Action", ["Start", "Stop", "Delete"])
        db_instance_identifier = st.text_input("DB Instance Identifier")

        if action == "Start" and st.button("Execute"):
            response = start_rds_instance(db_instance_identifier)
            if isinstance(response, dict):
                st.success(f"Instance {db_instance_identifier} started successfully.")
            else:
                st.error(f"Error starting instance: {response}")

        elif action == "Stop" and st.button("Execute"):
            response = stop_rds_instance(db_instance_identifier)
            if isinstance(response, dict):
                st.success(f"Instance {db_instance_identifier} stopped successfully.")
            else:
                st.error(f"Error stopping instance: {response}")

        elif action == "Delete" and st.button("Execute"):
            response = delete_rds_instance(db_instance_identifier)
            if isinstance(response, dict):
                st.success(f"Instance {db_instance_identifier} deleted successfully.")
            else:
                st.error(f"Error deleting instance: {response}")

    elif task == "Run RDS Vulnerability Checker":
        st.subheader("RDS Vulnerability Checker")
        run_scanner.run_scanner()

if __name__ == "__main__":
    main()


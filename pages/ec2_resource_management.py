import streamlit as st

st.set_page_config(page_title="Ec2 Resource Management")

import boto3
from cryptography.fernet import Fernet
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE
import pages.ec2_vulnerability_checker as ec2_vulnerability_scanner
from menu import custom_menu

# List of AWS regions
AWS_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'ca-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3',
    'eu-central-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
    'ap-southeast-2', 'ap-south-1', 'sa-east-1'
]

# Display the custom menu
custom_menu()

st.title("EC2 Resource Management")

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

# Function to create EC2 instance
def create_ec2_instance(aws_access_key_id, aws_secret_access_key, region, instance_name, ami_id, instance_type, key_pair, subnet_id, security_group_id, ebs_volume_size):
    try:
        # Initialize Boto3 client for EC2
        ec2_client = boto3.client('ec2',
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key,
                                  region_name=region)

        # Create EC2 instance
        response = ec2_client.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            KeyName=key_pair,
            SubnetId=subnet_id,
            SecurityGroupIds=[security_group_id],
            MinCount=1,
            MaxCount=1,
            BlockDeviceMappings=[{
                'DeviceName': '/dev/sda1',
                'Ebs': {
                    'VolumeSize': ebs_volume_size,
                    'VolumeType': 'gp2'
                }
            }],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{
                    'Key': 'Name',
                    'Value': instance_name
                }]
            }]
        )

        instance_id = response['Instances'][0]['InstanceId']
        return instance_id
    except Exception as e:
        st.error(f"Error creating EC2 instance: {e}")
        return None

# Function to list EC2 instances in a region
def list_ec2_instances(aws_access_key_id, aws_secret_access_key, region):
    try:
        ec2_client = boto3.client('ec2',
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key,
                                  region_name=region)
        instances = ec2_client.describe_instances()
        return instances['Reservations']
    except Exception as e:
        st.error(f"Error listing EC2 instances: {e}")
        return []

# Function to start, stop, or terminate an instance
def manage_ec2_instance(action, instance_id, aws_access_key_id, aws_secret_access_key, region):
    try:
        ec2_client = boto3.client('ec2',
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key,
                                  region_name=region)
        if action == 'start':
            ec2_client.start_instances(InstanceIds=[instance_id])
            st.success(f"Instance {instance_id} started successfully.")
        elif action == 'stop':
            ec2_client.stop_instances(InstanceIds=[instance_id])
            st.success(f"Instance {instance_id} stopped successfully.")
        elif action == 'terminate':
            ec2_client.terminate_instances(InstanceIds=[instance_id])
            st.success(f"Instance {instance_id} terminated successfully.")
    except Exception as e:
        st.error(f"Error {action} instance {instance_id}: {e}")

# Main function
def main():
    task = st.selectbox("What would you like to do today?", ["Create EC2 Instance", "List EC2 Instances", "Manage EC2 Instance", "Run EC2 Vulnerability Checker"])

    if task == "Create EC2 Instance":
        st.subheader("Create EC2 Instance")
        with st.form("ec2_instance_form"):
            instance_name = st.text_input("Enter Instance Name")
            ami_id = st.text_input("Enter AMI ID")
            instance_type = st.selectbox("Select Instance Type", ["t2.micro", "t2.small", "t2.medium"])
            key_pair = st.text_input("Enter Key Pair Name")
            subnet_id = st.text_input("Enter Subnet ID")
            security_group_id = st.text_input("Enter Security Group ID")
            region = st.selectbox("Select AWS Region", AWS_REGIONS)
            ebs_volume_size = st.number_input("Enter EBS Volume Size (in GB)", min_value=1, step=1)

            col1, col_spacer, col2 = st.columns([1, 2, 1])
            with col1:
                submit_button = st.form_submit_button("Create EC2 Instance")
            with col2:
                return_button = st.form_submit_button("↩")

        if submit_button:
            instance_id = create_ec2_instance(aws_access_key_id, aws_secret_access_key, region, instance_name, ami_id, instance_type, key_pair, subnet_id, security_group_id, ebs_volume_size)
            if instance_id:
                st.success(f"EC2 instance '{instance_id}' created successfully.")

        if return_button:
            st.write("Redirecting to the previous page...")
            #st.experimental_rerun()
            st.switch_page("pages/chatbot.py")

    elif task == "List EC2 Instances":
        st.subheader("List EC2 Instances")
        with st.form("list_instances_form"):
            region = st.selectbox("Select AWS Region", AWS_REGIONS)
            list_button = st.form_submit_button("List Instances")

        if list_button:
            instances = list_ec2_instances(aws_access_key_id, aws_secret_access_key, region)
            if instances:
                for reservation in instances:
                    for instance in reservation['Instances']:
                        st.write(f"Instance ID: {instance['InstanceId']}")
                        st.write(f"State: {instance['State']['Name']}")
                        st.write(f"Instance Type: {instance['InstanceType']}")
                        st.write(f"Public IP: {instance.get('PublicIpAddress', 'N/A')}")
                        st.write("---")
            else:
                st.write("No instances found.")

    elif task == "Manage EC2 Instance":
        st.subheader("Manage EC2 Instance")
        with st.form("manage_instance_form"):
            instance_id = st.text_input("Enter Instance ID")
            action = st.selectbox("Select Action", ["start", "stop", "terminate"])
            region = st.selectbox("Select AWS Region", AWS_REGIONS)
            manage_button = st.form_submit_button("Execute")

        if manage_button:
            manage_ec2_instance(action, instance_id, aws_access_key_id, aws_secret_access_key, region)

    elif task == "Run EC2 Vulnerability Checker":
        st.subheader("EC2 Vulnerability Checker")
        ec2_vulnerability_scanner.ec2_vulnerability_scanner()

if __name__ == "__main__":
    main()


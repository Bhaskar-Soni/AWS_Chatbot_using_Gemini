import streamlit as st

st.set_page_config(page_title="VPC Resource Management")

import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
import time
from cryptography.fernet import Fernet
from menu import custom_menu  # Import the custom menu function
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE
import pages.vpc_vulnerability_checker as vpc_vuln_checker

# Display the custom menu
custom_menu()

st.title("VPC Resources Management")

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

def create_vpc(cidr_block, instance_tenancy, region):
    try:
        ec2_client = boto3.client('ec2',
                                  region_name=region,
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key)

        response = ec2_client.create_vpc(
            CidrBlock=cidr_block,
            InstanceTenancy=instance_tenancy
        )

        return response
    except Exception as e:
        return str(e)

def create_subnet(vpc_id, cidr_block, availability_zone, region):
    try:
        ec2_client = boto3.client('ec2',
                                  region_name=region,
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key)

        response = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr_block,
            AvailabilityZone=availability_zone
        )

        return response
    except Exception as e:
        return str(e)

def create_route_table(vpc_id, region):
    try:
        ec2_client = boto3.client('ec2',
                                  region_name=region,
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key)

        response = ec2_client.create_route_table(
            VpcId=vpc_id
        )

        return response
    except Exception as e:
        return str(e)

def list_vpcs(region):
    try:
        ec2_client = boto3.client('ec2',
                                  region_name=region,
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key)

        response = ec2_client.describe_vpcs()

        return response
    except NoCredentialsError:
        return "Credentials not available."
    except PartialCredentialsError:
        return "Incomplete credentials provided."
    except Exception as e:
        return str(e)

def main():
    task = st.selectbox("What would you like to do today?", [
        "Create VPC",
        "Create Subnet",
        "Create Route Table",
        "List VPCs",
        "Manage VPC",
        "Run VPC Vulnerability Checker"
    ])

    if task == "Create VPC":
        st.write("Enter VPC Details")

        # Create a form for user input
        with st.form("vpc_form"):
            cidr_block = st.text_input("CIDR Block (e.g., 10.0.0.0/16)")
            instance_tenancy = st.selectbox("Instance Tenancy", ["default", "dedicated"])
            region = st.selectbox("Region", ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"], index=["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"].index(default_region))

            col1, col_spacer, col2 = st.columns([1, 2, 1])
            with col1:
                submit_button = st.form_submit_button("Create VPC")
            with col2:
                return_button = st.form_submit_button("↩")

        # Handle VPC form submission
        if submit_button:
            if not cidr_block:
                st.warning("Please fill in all required fields.")
            else:
                response = create_vpc(cidr_block, instance_tenancy, region)
                if isinstance(response, dict) and 'Vpc' in response:
                    st.success("VPC created successfully!")
                    st.write("VPC ID:", response['Vpc']['VpcId'])
                    # Display redirecting message with countdown
                    countdown_text = st.empty()
                    for i in range(10, 0, -1):
                        countdown_text.write(f"Redirecting to the chatbot in {i} seconds...")
                        time.sleep(1)
                    st.write("Redirecting to the Chatbot...")
                    st.switch_page("pages/chatbot.py")
                else:
                    st.error("Error creating VPC:")
                    st.error(response)

        # Handle return button click
        if return_button:
            st.write("Redirecting to the previous page...")
            st.switch_page("pages/chatbot.py")

    elif task == "Create Subnet":
        st.write("Enter Subnet Details")

        # Create a form for user input
        with st.form("subnet_form"):
            vpc_id = st.text_input("VPC ID")
            cidr_block = st.text_input("CIDR Block (e.g., 10.0.1.0/24)")
            availability_zone = st.text_input("Availability Zone")
            region = st.selectbox("Region", ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"], index=["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"].index(default_region))

            col1, col_spacer, col2 = st.columns([1, 2, 1])
            with col1:
                submit_button = st.form_submit_button("Create Subnet")
            with col2:
                return_button = st.form_submit_button("↩")

        # Handle Subnet form submission
        if submit_button:
            if not vpc_id or not cidr_block or not availability_zone:
                st.warning("Please fill in all required fields.")
            else:
                response = create_subnet(vpc_id, cidr_block, availability_zone, region)
                if isinstance(response, dict) and 'Subnet' in response:
                    st.success("Subnet created successfully!")
                    st.write("Subnet ID:", response['Subnet']['SubnetId'])
                else:
                    st.error("Error creating Subnet:")
                    st.error(response)

        # Handle return button click
        if return_button:
            st.write("Redirecting to the previous page...")
            st.switch_page("pages/chatbot.py")

    elif task == "Create Route Table":
        st.write("Enter Route Table Details")

        # Create a form for user input
        with st.form("route_table_form"):
            vpc_id = st.text_input("VPC ID")
            region = st.selectbox("Region", ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"], index=["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"].index(default_region))

            col1, col_spacer, col2 = st.columns([1, 2, 1])
            with col1:
                submit_button = st.form_submit_button("Create Route Table")
            with col2:
                return_button = st.form_submit_button("↩")

        # Handle Route Table form submission
        if submit_button:
            if not vpc_id:
                st.warning("Please fill in all required fields.")
            else:
                response = create_route_table(vpc_id, region)
                if isinstance(response, dict) and 'RouteTable' in response:
                    st.success("Route Table created successfully!")
                    st.write("Route Table ID:", response['RouteTable']['RouteTableId'])
                else:
                    st.error("Error creating Route Table:")
                    st.error(response)

        # Handle return button click
        if return_button:
            st.write("Redirecting to the previous page...")
            st.switch_page("pages/chatbot.py")

    elif task == "List VPCs":
        st.write("Listing VPCs in different regions")

        for region_name in ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"]:
            try:
                ec2_client = boto3.client('ec2',
                                          region_name=region_name,
                                          aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key)
                response = ec2_client.describe_vpcs()

                if response and 'Vpcs' in response:
                    st.write(f"Region: {region_name}")
                    for vpc in response['Vpcs']:
                        st.write(f"VPC ID: {vpc['VpcId']}")
                        st.write(f"CIDR Block: {vpc['CidrBlock']}")
                        st.write("---")
                else:
                    st.write(f"No VPCs found in {region_name}")
            except NoCredentialsError:
                st.error(f"Credentials not available for {region_name}")
            except PartialCredentialsError:
                st.error(f"Incomplete credentials provided for {region_name}")
            except Exception as e:
                st.error(f"Error listing VPCs in {region_name}: {str(e)}")

    elif task == "Manage VPC":
        st.write("Manage VPCs")

        vpc_id = st.text_input("Enter VPC ID")

        if vpc_id:
            st.write(f"Selected VPC ID: {vpc_id}")
            option = st.selectbox("Select an action", ["View Resource Map", "Edit VPC", "Delete VPC"])

            if option == "View Resource Map":
                st.write(f"Resource map for VPC: {vpc_id}")

                try:
                    # Fetch subnets associated with the VPC
                    ec2_client = boto3.client('ec2',
                                              region_name=default_region,
                                              aws_access_key_id=aws_access_key_id,
                                              aws_secret_access_key=aws_secret_access_key)
                    
                    subnet_response = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])

                    if subnet_response and 'Subnets' in subnet_response:
                        st.write("Subnets:")
                        for subnet in subnet_response['Subnets']:
                            st.write(f"Subnet ID: {subnet['SubnetId']}, CIDR Block: {subnet['CidrBlock']}")
                        st.write("---")
                    else:
                        st.write("No subnets found for this VPC.")

                    # Fetch route tables associated with the VPC
                    route_table_response = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])

                    if route_table_response and 'RouteTables' in route_table_response:
                        st.write("Route Tables:")
                        for route_table in route_table_response['RouteTables']:
                            st.write(f"Route Table ID: {route_table['RouteTableId']}")
                            st.write("---")
                    else:
                        st.write("No route tables found for this VPC.")

                except Exception as e:
                    st.error(f"Error fetching resources for VPC {vpc_id}: {str(e)}")

            elif option == "Edit VPC":
                st.write("Edit VPC")
                st.write("Currently, AWS does not support direct editing of VPC configurations.")
                st.write("To modify a VPC, you would need to delete it and recreate it with updated parameters.")

            elif option == "Delete VPC":
                st.write("Delete VPC")
                st.warning("This action will permanently delete the selected VPC and its associated resources.")
                confirmation = st.checkbox("I understand, proceed with deletion.")

                if confirmation:
                    try:
                        ec2_client = boto3.client('ec2',
                                                  region_name=default_region,
                                                  aws_access_key_id=aws_access_key_id,
                                                  aws_secret_access_key=aws_secret_access_key)
                        
                        # First, disassociate and delete all subnets associated with the VPC
                        subnet_response = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                        
                        for subnet in subnet_response['Subnets']:
                            ec2_client.delete_subnet(SubnetId=subnet['SubnetId'])

                        # Next, delete all route tables associated with the VPC
                        route_table_response = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])

                        for route_table in route_table_response['RouteTables']:
                            ec2_client.delete_route_table(RouteTableId=route_table['RouteTableId'])

                        # Finally, delete the VPC itself
                        ec2_client.delete_vpc(VpcId=vpc_id)

                        st.success(f"VPC {vpc_id} and its associated resources successfully deleted.")

                    except Exception as e:
                        st.error(f"Error deleting VPC {vpc_id}: {str(e)}")

        else:
            st.warning("Please enter a VPC ID to manage.")

    elif task == "Run VPC Vulnerability Checker":
        st.subheader("VPC Vulnerability Checker")
        vpc_vuln_checker.vpc_vuln_checker()	

if __name__ == "__main__":
    main()


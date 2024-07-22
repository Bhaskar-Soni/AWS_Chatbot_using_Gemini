# pages/current_month_billing.py
import streamlit as st
import boto3
from datetime import datetime, timedelta
import pandas as pd
from cryptography.fernet import Fernet
#from menu import custom_menu  # Import the custom menu function
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE

# Display the custom menu
#custom_menu()

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

# Load and decrypt AWS credentials
aws_access_key_id, aws_secret_access_key = load_aws_credentials()

# Initialize boto3 client with decrypted credentials
client = boto3.client(
    'ce',
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name='us-east-1'  # Cost Explorer is available only in us-east-1
)

# Function to display the current month billing dashboard
def current_billing():
    st.title("AWS Current Month Billing Dashboard")

    # Get current date
    today = datetime.today()
    start_date = today.replace(day=1).strftime('%Y-%m-%d')
    end_date = today.strftime('%Y-%m-%d')

    try:
        # Call Cost Explorer API to get daily costs for the current month
        response = client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date,
                'End': end_date
            },
            Granularity='DAILY',
            Metrics=['UnblendedCost']
        )

        # Extract daily costs
        daily_costs = []
        dates = []
        for result in response['ResultsByTime']:
            date = result['TimePeriod']['Start']
            amount = float(result['Total']['UnblendedCost']['Amount'])
            daily_costs.append(amount)
            dates.append(date)

        # Create a DataFrame for the daily costs
        df = pd.DataFrame({
            'Date': dates,
            'Cost': daily_costs
        })
        df['Date'] = pd.to_datetime(df['Date'])

        # Display the current month's total billing
        total_cost = df['Cost'].sum()
        st.success(f"Current month's total billing: {total_cost:.2f} USD")

        # Display the bar chart of daily costs
        st.bar_chart(df.set_index('Date')['Cost'])

    except Exception as e:
        st.error(f"Error retrieving billing information: {e}")

# Export the display function for import in other modules
__all__ = ['current_billing']

# If this script is run directly, execute the display function
if __name__ == "__main__":
    current_billing()

import streamlit as st

st.set_page_config(page_title="Cost Optimization")

import boto3
import pandas as pd
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import requests
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE, GEMINI_API_KEY, GEMINI_API_ENDPOINT
from menu import custom_menu

# Display the custom menu
custom_menu()

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

# Load and decrypt AWS credentials
aws_access_key_id, aws_secret_access_key, region = load_credentials()

def get_aws_cost_and_usage(start_date, end_date):
    client = boto3.client(
        'ce',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )
    response = client.get_cost_and_usage(
        TimePeriod={'Start': start_date, 'End': end_date},
        Granularity='MONTHLY',
        Metrics=['UnblendedCost'],
        GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
    )
    return response

def generate_cost_saving_suggestions(data):
    cost_summary = ""
    for service in data:
        service_name = service['Keys'][0]
        amount = float(service['Metrics']['UnblendedCost']['Amount'])
        cost_summary += f"{service_name}: ${amount:.2f}\n"
    
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        "contents": [{
            "parts": [{
                "text": (
                    "You are an expert in AWS cost optimization. Analyze the following AWS service costs and provide a detailed, step-by-step guide on how to reduce the costs for each service. The guide should include specific actions, best practices, and potential savings opportunities for each service, as well as recommendations for services that might be incurring costs without being used. The response should be structured to help a user understand how to manage and optimize their AWS billing effectively "
                    "provide detailed and actionable cost-saving suggestions:\n\n"
                    f"{cost_summary}\n\n"
                    "Suggestions:"
                )
            }]
        }]
    }

    response = requests.post(
        f'{GEMINI_API_ENDPOINT}?key={GEMINI_API_KEY}',  # Include API key in the query string
        headers=headers,
        json=payload
    )
    
    if response.status_code == 200:
        response_json = response.json()
        if 'candidates' in response_json and len(response_json['candidates']) > 0:
            suggestions = response_json['candidates'][0]['content']['parts'][0]['text'].strip()
        else:
            suggestions = "No suggestions available."
    else:
        suggestions = f"Error: {response.status_code}, {response.text}"
    
    return suggestions

def main():
    st.subheader('Cost Optimization Suggestions by Gemini')

    # Date range selection
    today = datetime.today()
    start_date = st.date_input('Start date', today - timedelta(days=30))
    end_date = st.date_input('End date', today)

    if st.button('Analyze'):
        # Fetch AWS cost and usage data
        data = get_aws_cost_and_usage(start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d'))

        # Process data
        if 'ResultsByTime' in data:
            cost_data = data['ResultsByTime'][0]['Groups']
            suggestions = generate_cost_saving_suggestions(cost_data)

            # Display results
            st.subheader('Cost Analysis')
            for service in cost_data:
                st.write(f"{service['Keys'][0]}: ${float(service['Metrics']['UnblendedCost']['Amount']):.2f}")

            st.subheader('Cost-Saving Suggestions')
            st.write(suggestions)

            # Indicate that analysis has been performed
            st.session_state.analysis_done = True
        else:
            st.error('No cost data available for the selected period.')
            st.session_state.analysis_done = False
    
    # Show the "Chat with Cost Optimize" button if analysis is done
    if st.session_state.get('analysis_done', False):
        st.write("Not satisfied with this output? Click the button to start chatting with the cost optimizer bot.")
        if st.button("Chat with Bot"):
            st.write("Redirecting to the previous page...")
            st.switch_page("pages/cost_optimization_chatbot.py")

if __name__ == '__main__':
    main()

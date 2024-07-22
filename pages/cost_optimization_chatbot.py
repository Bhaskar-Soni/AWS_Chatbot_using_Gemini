import streamlit as st

st.set_page_config(page_title="AWS Chatbot")

import os
import google.generativeai as genai
from datetime import datetime, timedelta
import boto3
from cryptography.fernet import Fernet
import requests
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE, GEMINI_API_KEY, GEMINI_API_ENDPOINT
from menu import custom_menu
import re

# Display the custom menu
custom_menu()

# Set Google API key
os.environ['GOOGLE_API_KEY'] = GEMINI_API_KEY
genai.configure(api_key=os.environ['GOOGLE_API_KEY'])

# Create the Model
model = genai.GenerativeModel('gemini-pro')

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = [
        {
            "role": "assistant",
            "content": "Hi there! I can help you with AWS cost-related questions and suggestions. Ask me about reducing costs, managing your AWS billing, analyzing your AWS expenses, or checking your current month's cost!"
        }
    ]

# Display chat messages from history on app rerun
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Function to load and decrypt AWS credentials
def load_credentials():
    with open(CREDENTIALS_FILE, 'r') as f:
        lines = f.readlines()
        access_key = decrypt_data(lines[0].split(': ')[1].strip())
        secret_key = decrypt_data(lines[1].split(': ')[1].strip())
        region = lines[2].split(': ')[1].strip()
        return access_key, secret_key, region

# Initialize Fernet cipher suite
key = open(ENCRYPTION_KEY_FILE, 'rb').read()
cipher_suite = Fernet(key)

# Function to decrypt data
def decrypt_data(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
    return decrypted_data.decode()

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
                    "You are an expert in AWS cost optimization. Given the following AWS service costs, "
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

def get_current_month_cost():
    today = datetime.today()
    start_date = today.replace(day=1).strftime('%Y-%m-%d')
    end_date = (today + timedelta(days=31)).replace(day=1).strftime('%Y-%m-%d')
    data = get_aws_cost_and_usage(start_date, end_date)
    if 'ResultsByTime' in data:
        cost_data = data['ResultsByTime'][0]['Groups']
        return cost_data
    else:
        return None
    
def get_cost_for_date_range(start_date, end_date):
    data = get_aws_cost_and_usage(start_date, end_date)
    if 'ResultsByTime' in data:
        cost_data = data['ResultsByTime'][0]['Groups']
        cost_summary = ""
        for service in cost_data:
            service_name = service['Keys'][0]
            amount = float(service['Metrics']['UnblendedCost']['Amount'])
            cost_summary += f"{service_name}: ${amount:.2f}\n"
        
        return cost_summary
    else:
        return "No cost data available for the selected period."

def llm_function(query):
    # Define phrases for different types of cost-related questions
    current_cost_phrases = [
        "this month cost", "current month cost", "this month's aws bill", 
        "how much is my aws bill", "my aws bill for this month", 
        "aws bill for this month", "tell me the cost for this month", 
        "show me my aws costs for this month", "current month's billing", 
        "how much is my aws cost this month"
    ]
    
    cost_reduction_phrases = [
        "reduce aws costs", "how to save on aws", "aws cost reduction", 
        "reduce billing", "cut aws expenses", "optimize aws costs", 
        "cost saving", "cost reduction guide", "aws cost optimization", 
        "how can I reduce my aws bill", "suggestions for saving on aws"
    ]
    
    analyze_cost_phrases = [
        "analyze my aws account's cost", "analyze aws cost", 
        "review my aws expenses", "aws cost analysis", 
        "evaluate my aws billing", "cost analysis", 
        "provide suggestions for my aws costs"
    ]
    date_range_pattern = r'from (\d{4}-\d{2}-\d{2}) to (\d{4}-\d{2}-\d{2})'

    query_lower = query.lower()

    # Check if the query matches any of the cost-related phrases
    if any(phrase in query_lower for phrase in current_cost_phrases):
        # Get current month's cost data
        cost_data = get_current_month_cost()
        if cost_data:
            cost_summary = ""
            for service in cost_data:
                service_name = service['Keys'][0]
                amount = float(service['Metrics']['UnblendedCost']['Amount'])
                cost_summary += f"{service_name}: ${amount:.2f}\n"
            
            cost_summary += "\nTax: $0.00"  # Add this line to include the tax information
            response_text = f"Here is the breakdown of your AWS costs for this month:\n\n{cost_summary}"
        else:
            response_text = "Unable to retrieve cost data for the current month."
    elif any(phrase in query_lower for phrase in cost_reduction_phrases):
        # Get cost and usage data for the last 30 days
        today = datetime.today()
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
        end_date = today.strftime('%Y-%m-%d')
        data = get_aws_cost_and_usage(start_date, end_date)
        
        if 'ResultsByTime' in data:
            cost_data = data['ResultsByTime'][0]['Groups']
            suggestions = generate_cost_saving_suggestions(cost_data)
            response_text = suggestions
        else:
            response_text = 'No cost data available for the selected period.'
    elif any(phrase in query_lower for phrase in analyze_cost_phrases):
        # Get current month's cost data
        cost_data = get_current_month_cost()
        if cost_data:
            cost_summary = ""
            for service in cost_data:
                service_name = service['Keys'][0]
                amount = float(service['Metrics']['UnblendedCost']['Amount'])
                cost_summary += f"{service_name}: ${amount:.2f}\n"
            
            cost_summary += "\nTax: $0.00"  # Add this line to include the tax information
            # Generate cost-saving suggestions based on the current month's cost data
            suggestions = generate_cost_saving_suggestions(cost_data)
            response_text = (
                f"Here is the breakdown of your AWS costs for this month:\n\n{cost_summary}\n\n"
                f"Suggestions for reducing costs:\n{suggestions}"
            )
        else:
            response_text = "Unable to retrieve cost data for the current month."
    elif re.search(date_range_pattern, query_lower):
        # Extract dates from the query and get cost data for the specified date range
        match = re.search(date_range_pattern, query_lower)
        start_date = match.group(1)
        end_date = match.group(2)
        cost_summary = get_cost_for_date_range(start_date, end_date)
        response_text = f"Here is the breakdown of your AWS costs from {start_date} to {end_date}:\n\n{cost_summary}"
    elif "help" in query_lower or "commands" in query_lower:
        response_text = (
            "Available Commands for AWS Cost Management:\n"
            "- *Current Month Cost*: Ask about the cost breakdown for the current month.\n"
            "- Show me the cost from YYYY-MM-DD to YYYY-MM-DD.\n"
            "- *Cost Reduction*: Ask for ways to save on your AWS costs.\n"
            "- *Cost Analysis*: Ask for a detailed analysis of your AWS costs and suggestions for reduction.\n"
            "\nExamples:\n"
            "- 'What are my AWS costs for this month?'\n"
            "- 'How can I reduce my AWS spending?'\n"
            "- 'Analyze my AWS account's cost and tell me the suggestions.'\n"
        )
    else:
        # Pass the query to the Gemini API with the cost-related prompt
        headers = {
            'Content-Type': 'application/json'
        }
        prompt = (
            "You are an expert chatbot designed to assist users with AWS cost-related questions. "
            "Your primary focus is to provide information and suggestions related to AWS billing, cost management, and cost optimization. "
            "Respond only to questions about AWS costs, including cost breakdowns, current costs, and ways to save on AWS bills. "
            "If a user asks about anything other than AWS cost management or makes an invalid request, politely redirect them to ask about AWS costs or inform them that you can only assist with AWS cost-related questions."
        )
        payload = {
            "contents": [{
                "parts": [{
                    "text": f"{prompt}\n\nUser Query: {query}\n\nResponse:"
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
                response_text = response_json['candidates'][0]['content']['parts'][0]['text'].strip()
            else:
                response_text = "No suggestions available."
        else:
            response_text = f"Error: {response.status_code}, {response.text}"

    # Displaying the Assistant Message
    with st.chat_message("assistant"):
        st.markdown(response_text)

    # Storing the User Message
    st.session_state.messages.append(
        {
            "role": "user",
            "content": query
        }
    )

    # Storing the Assistant Message
    st.session_state.messages.append(
        {
            "role": "assistant",
            "content": response_text
        }
    )

# Accept user input
query = st.chat_input("Ask me anything about AWS costs!")

# Calling the Function when Input is Provided
if query:
    # Displaying the User Message
    with st.chat_message("user"):
        st.markdown(query)

    llm_function(query)

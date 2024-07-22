import streamlit as st

st.set_page_config(page_title="AWS Chatbot")

import os
import time
import google.generativeai as genai
from pages.ec2_operations import *
from menu import custom_menu
from pages.ec2_tools_installation import *
from transformers import pipeline, AutoModelForSequenceClassification, AutoTokenizer
from pages.manual_answers import *
from config import GEMINI_API_KEY

# Display the custom menu
custom_menu()

# Title for Chatbot
st.title("AWS Chatbot - By Bhaskar Soni")

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
            "content": "Ask me anything | *You can use Help*"
        }
    ]

# Helper function to append messages to session state
def append_messages(query, response_text):
    st.session_state.messages.append({
        "role": "user",
        "content": query
    })
    st.session_state.messages.append({
        "role": "assistant",
        "content": response_text
    })
    with st.chat_message("assistant"):
        st.markdown(response_text)

# Initialize state for input
if "awaiting_input" not in st.session_state:
    st.session_state.awaiting_input = None
if "instance_id" not in st.session_state:
    st.session_state.instance_id = ""

# Display chat messages from history on app rerun
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Load the pre-trained BART model for classification from Hugging Faces
from transformers import pipeline			  
classifier = pipeline("zero-shot-classification",
                      model="facebook/bart-large-mnli",
                      tokenizer="facebook/bart-large-mnli")

# Define labels for classification
labels = ["technical", "non-technical"]

# Define a set of keywords that should not be answered
non_technical_keywords = {"weather", "news", "sports", "movies"} # Define more keywords for better accuracy and result

# Function to process and store Query and Response
def llm_function(query):
    response_text = ""

    if st.session_state.awaiting_input == "instance_id":
        st.session_state.instance_id = query
        st.session_state.awaiting_input = None
        try:
            if st.session_state.action == "check_ram":
                ram_info = check_ram(st.session_state.instance_id)
                response_text = ram_info
            elif st.session_state.action == "check_cpus":
                cpus_info = check_cpus(st.session_state.instance_id)
                response_text = cpus_info
            elif st.session_state.action == "check_storage":
                storage_info = check_storage(st.session_state.instance_id)
                response_text = storage_info
            elif st.session_state.action == "check_open_ports":
                open_ports_info = check_open_ports(st.session_state.instance_id)
                response_text = open_ports_info
            elif st.session_state.action == "check_os_version":
                os_version_info = check_os_version(st.session_state.instance_id)
                response_text = os_version_info
            elif st.session_state.action == "check_kernel_version":
                kernel_version_info = check_kernel_version(st.session_state.instance_id)
                response_text = kernel_version_info
            elif st.session_state.action == "list_users":
                users_info = list_users(st.session_state.instance_id)
                response_text = users_info
            elif st.session_state.action == "install_apache":
                apache_installation_info = install_apache(st.session_state.instance_id)
                response_text = apache_installation_info
            elif st.session_state.action == "internal_audit_report":
                internal_audit_report_info = internal_audit_report(st.session_state.instance_id)
                response_text = internal_audit_report_info
            elif st.session_state.action == "install_wordpress":
                wordpress_info = install_wordpress(st.session_state.instance_id)
                response_text = wordpress_info
            elif st.session_state.action == "install_mysql":
                mysql_installation_info = install_mysql(st.session_state.instance_id)
                response_text = mysql_installation_info
            elif st.session_state.action == "install_dvwa":
                dvwa_installation_info = install_dvwa(st.session_state.instance_id)
                response_text = dvwa_installation_info
            elif st.session_state.action == "install_php_and_configure":
                php_installation_info = install_php_and_configure(st.session_state.instance_id)
                response_text = php_installation_info
            elif st.session_state.action == "run_command":
                command_info = run_command_on_instance(st.session_state.instance_id, st.session_state.command_to_run)
                response_text = command_info
        except Exception as e:
            response_text = f"Error: {e}"
        
    elif st.session_state.awaiting_input == "file_path" and st.session_state.action == "check_first_n_lines":
        first_n_lines = check_first_n_lines(query, st.session_state.n_lines)
        response_text = first_n_lines
        st.session_state.awaiting_input = None
        st.session_state.action = None
        st.session_state.n_lines = None

    elif st.session_state.awaiting_input == "file_path" and st.session_state.action == "check_last_n_lines":
        last_n_lines = check_last_n_lines(query, st.session_state.n_lines)
        response_text = last_n_lines
        st.session_state.awaiting_input = None
        st.session_state.action = None
        st.session_state.n_lines = None

    else:
        if query.lower().startswith("run command:"):
            command = query[len("run command:"):].strip()
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "run_command"
            st.session_state.command_to_run = command
            response_text = "Please enter the instance ID:"
        elif 'check ram' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "check_ram"
            response_text = "Please enter the instance ID:"
        elif 'check cpus' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "check_cpus"
            response_text = "Please enter the instance ID:"
        elif 'check storage' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "check_storage"
            response_text = "Please enter the instance ID:"
        elif 'check open ports' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "check_open_ports"
            response_text = "Please enter the instance ID:"
        elif 'check os version' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "check_os_version"
            response_text = "Please enter the instance ID:"
        elif 'check kernel version' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "check_kernel_version"
            response_text = "Please enter the instance ID:"
        elif 'check first' in query.lower():
            # Extract the number of lines from the query
            try:
                n = int(query.split()[-2])  # assuming the query format: "check first {n} lines"
            except ValueError:
                response_text = "Please provide a valid number of lines to check."
                with st.chat_message("assistant"):
                    st.markdown(response_text)
                return
            
            st.session_state.awaiting_input = "file_path"
            st.session_state.action = "check_first_n_lines"
            st.session_state.n_lines = n
            response_text = f"Please enter the file path to check its first {n} lines:"
        elif 'check last' in query.lower():
            # Extract the number of lines from the query
            try:
                n = int(query.split()[-2])  # assuming the query format: "check last {n} lines"
            except ValueError:
                response_text = "Please provide a valid number of lines to check."
                with st.chat_message("assistant"):
                    st.markdown(response_text)
                return
            
            st.session_state.awaiting_input = "file_path"
            st.session_state.action = "check_last_n_lines"
            st.session_state.n_lines = n
            response_text = f"Please enter the file path to check its last {n} lines:"
        elif 'list instances' in query.lower():
            try:
                instance_info = list_instances()
                response_text = instance_info
            except Exception as e:
                response_text = f"Error: {e}"
        elif 'list users' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "list_users"
            response_text = "Please enter the instance ID:"
        elif 'install apache' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "install_apache"
            response_text = "Please enter the instance ID:"
        elif 'run internal audit on instance' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "internal_audit_report"
            response_text = "Please enter the instance ID:"
        elif 'install wordpress' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "install_wordpress"
            response_text = "Please enter the instance ID:"
        elif 'install mysql' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "install_mysql"
            response_text = "Please enter the instance ID:"
        elif 'install dvwa' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "install_dvwa"
            response_text = "Please enter the instance ID:"
        elif 'install php' in query.lower():
            st.session_state.awaiting_input = "instance_id"
            st.session_state.action = "install_php_and_configure"
            response_text = "Please enter the instance ID:"
        elif 'ec2 resource management' in query.lower():
            response_text = "Redirecting to EC2 Resource Management..."
            append_messages(query, response_text)
            time.sleep(1)
            st.switch_page("pages/ec2_resource_management.py")
            return
        elif 'iam resource management' in query.lower():
            response_text = "Redirecting to IAM Resource Management..."
            append_messages(query, response_text)
            time.sleep(1)
            st.switch_page("pages/iam_resource_management.py")
            return
        elif 'rds resource management' in query.lower():
            response_text = "Redirecting to RDS Resource Management..."
            append_messages(query, response_text)
            time.sleep(1)
            st.switch_page("pages/rds_resource_management.py")
            return
        elif 's3 resource management' in query.lower():
            response_text = "Redirecting to S3 Resource Management..."
            append_messages(query, response_text)
            time.sleep(1)
            st.switch_page("pages/s3_resource_management.py")
            return
        elif 'vpc resource management' in query.lower():
            response_text = "Redirecting to VPC Resource Management..."
            append_messages(query, response_text)
            time.sleep(1)
            st.switch_page("pages/vpc_resource_management.py")
            return
        elif 'generate an audit report' in query.lower():
            response_text = "Redirecting to Report Generation..."
            append_messages(query, response_text)
            time.sleep(1)
            st.switch_page("pages/audit_report.py")
            return
        elif 'help' == query.lower():
            response_text = "Available Commands:\n" \
                            "- Help Resource Management\n" \
                            "- Help Ec2 Basic Operations\n" \
                            "- Help Tools Installation on ec2\n" \
                            "- Help Report Generation"
        elif "help resource management" == query.lower():
            response_text = "Available Commands:\n" \
                            "- *EC2* Resource Management\n" \
                            "- *IAM* Resource Management\n" \
                            "- *RDS* Resource Management\n" \
                            "- *S3* Resource Management\n" \
                            "- *VPC* Resource Management"
        elif 'help ec2 basic operations' == query.lower():
            response_text = "Available commands:\n" \
                            "- Check RAM\n" \
                            "- Check CPUs\n" \
                            "- Check Storage\n" \
                            "- Check Open Ports\n" \
                            "- Check OS Version\n" \
                            "- Check Kernel Version\n" \
                            "- List Instances\n" \
                            "- List Users\n" \
                            "- Check First n Lines | Ex: Check First 50 Lines\n" \
                            "- Check Last n Lines | Ex: Check Last 50 Lines\n" \
                            "- Run Command: command | Ex: Run Command: ls -la /home"
        elif 'help tools installation on ec2' == query.lower():
            response_text = "Available commands:\n" \
                            "- Install Apache Server\n" \
                            "- Install MySQL Database\n" \
                            "- Install PHP\n" \
                            "- Install Wordpress\n" \
                            "- Install DVWA"
        elif "help report generation" == query.lower():
            response_text = "Available Commands:\n" \
                            "- Generate an Audit Report\n" \
                            "- Run Internal Audit on instance"
        elif "hi" in query.lower() or "hello" in query.lower() or "hallo" in query.lower():
            response_text = hi_response(query)
        elif "who developed you" in query.lower() or "who develop you" in query.lower() or "who is your developer" in query.lower() or "who created you" in query.lower() or "who made you" in query.lower():
            response_text = creator_response(query)
        elif "how are you?" in query.lower() or "how are you" in query.lower() or "how are you doing" in query.lower():
            response_text = how_are_you_response(query)  
        elif "what’s up?" in query.lower() or "what’s up" in query.lower() or "how are you doing" in query.lower():
            response_text = whats_up_response(query)  
        elif "how old are you?" in query.lower() or "how old are you" in query.lower() or "what’s your age?" in query.lower():
            response_text = age_response(query) 
        
        # With Text Classification Code
        else:
            # Check if the query contains non-technical keywords
            if any(keyword in query.lower() for keyword in non_technical_keywords):
                non_technical_response = "I'm sorry, but I can only answer technical questions related to AWS."

                # Displaying the Assistant Message
                with st.chat_message("assistant"):
                    st.markdown(non_technical_response)

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
                        "content": non_technical_response
                    }
                )
            elif not any(keyword in query.lower() for keyword in non_technical_keywords):
                # Classify the query
                result = classifier(query, labels)
                classification = result["labels"][0]
                confidence = result["scores"][0]

                # Adjust this threshold based on your evaluation
                if classification == "technical" and confidence > 0.7:
                    response = model.generate_content(query)

                    # Displaying the Assistant Message
                    with st.chat_message("assistant"):
                        st.markdown(response.text)

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
                            "content": response.text
                        }
                    )
                else:
                    non_technical_response = "I'm sorry, but I can only answer technical questions related to AWS."

                    # Displaying the Assistant Message
                    with st.chat_message("assistant"):
                        st.markdown(non_technical_response)

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
                            "content": non_technical_response
                        }
                    )
    if str(response_text)!="":
        # Display the Assistant Message
        with st.chat_message("assistant"):
            st.markdown(response_text, unsafe_allow_html=True)
        # Store the User Message
        st.session_state.messages.append(
            {
                "role": "user",
                "content": query
            }
        )

        # Store the Assistant Message
        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": response_text
            }
        )
    else:
        pass
    # With Text Classification Code

# #Without Text Classification Code
#         else:
#              ## Without Text Classification Model Integration
#             response = model.generate_content(query)
#             response_text = response.text

# # Display the Assistant Message
#     with st.chat_message("assistant"):
#         st.markdown(response_text)

#     # Store the User Message
#     st.session_state.messages.append(
#         {
#             "role": "user",
#             "content": query
#         }
#     )

#     # Store the Assistant Message
#     st.session_state.messages.append(
#         {
#             "role": "assistant",
#             "content": response_text
#         }
#     )
# #Without Text Classification Code

# Accept user input
query = st.chat_input("What is up?")

# Calling the Function when Input is Provided
if query:
    # Display the User Message
    with st.chat_message("user"):
        st.markdown(query)

    llm_function(query)
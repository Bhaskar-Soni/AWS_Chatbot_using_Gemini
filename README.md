# AWS Chatbot

![3  Main Chatbot with Side Bar](https://github.com/user-attachments/assets/fb0261b5-bc70-4a55-882e-bdf860ec71fd)

## Welcome to our AWS Chatbot Application!

### Problem Summary
Traditional AWS resource management and security pose a challenge due to a lack of education and expertise among users. Many individuals face barriers in navigating and efficiently utilizing AWS services because of the complex nature of cloud computing. This complexity can lead to inefficient resource management, security vulnerabilities, and higher operational costs. Organizations utilizing AWS often encounter several key issues:
1. **Complexity in Resource Management**
2. **Security Vulnerabilities**
3. **Cost Management**
4. **Manual Auditing Processes**
5. **Other Issues**

### Motivation
The motivation behind developing an interactive AWS ChatBot stems from the need to democratize AWS resource management. By bridging the gap between AWS complexity and user knowledge, the ChatBot aims to empower a broader audience with efficient and accessible cloud management capabilities. This tool seeks to make AWS more user-friendly, enabling individuals and organizations to leverage AWS services effectively without requiring extensive expertise.

## Our Mission
Our mission is to provide a seamless and efficient way for users to manage their AWS resources. We aim to make cloud management easy, accessible, and secure through our advanced chatbot technology.

## Features
1. **Chatbot using Gemini API**
2. **Dynamic task execution on AWS**
3. **Tool Installation on Ec2 using Chatbot**
4. **Overall AWS account audit and report generation**
5. **Vulnerability analysis**
6. **Dynamic installation of tools on EC2**
7. **Internal audit report generation**
8. **Text Classification**
9. **Basic Pentest**
10. **Cost Optimization**

## Technology Used
1. **Text Classification**: [Facebook/bart-large-mnli](https://huggingface.co/facebook/bart-large-mnli)
2. **LLM Function**: Gemini API
3. **Python SDK for AWS**: Boto3
4. **Python Framework**: Streamlit
5. **Cloud Platform**: AWS
6. **External Audit Report integration**: [Scout2 from Github](https://github.com/nccgroup/Scout2)
7. **Internal Audit Report integration**: [LinuxAudit from Github](https://github.com/Bhaskar-Soni/linux_admin/blob/main/shell_scripts/linux_audit_with_html_report.sh)
8. **Encryption**: [Fernet Symmetric_Encryption](https://cryptography.io/en/latest/fernet/)

## Scout2 Acknowledgment
This project utilizes [Scout2](https://github.com/nccgroup/Scout2) for external audit report generation. Scout2 is developed and maintained by [NCC Group](https://www.nccgroup.com/). We acknowledge and thank the developers for their work on this valuable tool.

## Our Team

**Bhaskar Soni**  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/sonibhaskar)

================================================================

## How to Run the Project

## Step 1: Clone the repository
```
git clone https://github.com/Bhaskar-Soni/AWS_Chatbot_using_Gemini.git
```

## Step 2: Install Dependencies
```
cd AWS_Chatbot_using_Gemini
sudo chmod 755 -R ../app
pip install -r requirements.txt
```

## Step 3: Install required tools
```
sudo apt-get install nmap gobuster 
```

## Step 4: Run Streamlit App
```
streamlit run __main__.py

nohup streamlit run _main_.py & #Or run in background
```

## Step 5: Access the Application
```
Open your browser and navigate to: http://localhost:8501
```

## Requirements for Error-Free Execution
Ensure the following credentials and configurations are set up correctly:

## 1. AWS Credentials:
```
AWS Key
AWS Secret
AWS Region
```
These are automatically added to "app/credentials" when provided in the URL.

## 2. Paths:
In Config.py change these credentials:
```
PEM_FILE_PATH = Your Ec2 Access Key file name ##Store it in the same directory
GEMINI_API_KEY = Gemini API Key
```
---

© 2024 AWS Chatbot Application. All rights reserved.

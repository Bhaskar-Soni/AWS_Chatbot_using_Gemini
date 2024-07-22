import streamlit as st

st.set_page_config(page_title="About US")

from menu import custom_menu

# Display the custom menu
custom_menu()

content = """
<h2>Welcome to our AWS Chatbot Application!</h2>

## Problem Summary
Traditional AWS resource management and security poses a challenge due to a lack of education and expertise among users. Many individuals face barriers in navigating and efficiently utilizing AWS services because of the complex nature of cloud computing. This complexity can lead to inefficient resource management, security vulnerabilities, and higher operational costs. Organizations utilizing AWS often encounter several key issues:
  1. **Complexity in Resource Management**
  2. **Security Vulnerabilities**
  3. **Cost Management**
  4. **Manual Auditing Processes**
  5. **Other Issues**

## Motivation:
The motivation behind developing an interactive AWS ChatBot stems from the need to democratize AWS resource management. By bridging the gap between AWS complexity and user knowledge, the ChatBot aims to empower a broader audience with efficient and accessible cloud management capabilities. This tool seeks to make AWS more user-friendly, enabling individuals and organizations to leverage AWS services effectively without requiring extensive expertise.

## Our Mission
Our mission is to provide a seamless and efficient way for users to manage their AWS resources. We aim to make cloud management easy, accessible, and secure through our advanced chatbot technology.

## Features
1. **Chatbot using Gemini API**
2. **Dynamic task execution on AWS**
3. **Overall AWS account audit and report generation**
4. **Vulnerability analysis**
5. **Dynamic installation of tools on EC2**
6. **Internal audit report generation**
7. **Text Classification**
8. **Basic Pentest**
9. **Cost Optimization**

## Technology Used
1. **Text Classification**: Facebook/bart-large-mnli
2. **LLM Function**: Gemini API
3. **Python SDK for AWS**: Boto3
4. **Python Framework**: Streamlit
5. **Cloud Platform**: AWS
6. **External Audit Report integration**: Scout2 from [Github](https://github.com/nccgroup/Scout2)
7. **Internal Audit Report integration**: LinuxAudit from [Github](https://github.com/Bhaskar-Soni/linux_admin/blob/main/shell_scripts/linux_audit_with_html_report.sh)
8. **Encryption**: Fernet [Symmetric_Encryption](https://cryptography.io/en/latest/fernet/)

## Our Team

Bhaskar Soni
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/sonibhaskar)

## Contact Us
We'd love to hear from you! If you have any questions, feedback, or need support do reach me on [LinkedIn](https://www.linkedin.com/in/sonibhaskar).

Thank you for choosing our AWS Chatbot Application. We look forward to helping you manage your AWS resources more effectively!

---

© 2024 AWS Chatbot Application. All rights reserved.

"""
# Display the content with proper Markdown formatting
st.markdown(content, unsafe_allow_html=True)
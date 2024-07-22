import streamlit as st

st.set_page_config(page_title="Vulnerability Assessment")

from menu import custom_menu
import pages.ec2_vulnerability_checker as ec2_vulnerability_scanner
import pages.iam_security_checker as iam_checker
import pages.rds_vulnerability_scanner as run_scanner
import pages.s3_vulnerability_checker as s3_vuln_checker
import pages.vpc_vulnerability_checker as vpc_vuln_checker

# Display the custom menu
custom_menu()

st.markdown("<h1 style='text-align: center;'>Vulnerability Assessment</h1>", unsafe_allow_html=True)

# Dropdown menu example
def main():
    task = st.selectbox("Where would you like to run Vulnerability Assessment(VA) today?", ["Run VA on EC2", "Run VA on IAM", "Run VA on RDS", "Run VA on S3", "Run VA on VPC"])

    if task == "Run VA on EC2":
        st.subheader("EC2 Vulnerability Checker")
        ec2_vulnerability_scanner.ec2_vulnerability_scanner()
    elif task == "Run VA on IAM":
        st.subheader("IAM Vulnerability Checker")
        iam_checker.iam_checker()
    elif task == "Run VA on RDS":
        st.subheader("RDS Vulnerability Checker")
        run_scanner.run_scanner()
    elif task == "Run VA on S3":
        st.subheader("S3 Vulnerability Checker")
        s3_vuln_checker.s3_vuln_checker()
    elif task == "Run VA on VPC":
        st.subheader("VPC Vulnerability Checker")
        vpc_vuln_checker.vpc_vuln_checker()

if __name__ == "__main__":
    main()

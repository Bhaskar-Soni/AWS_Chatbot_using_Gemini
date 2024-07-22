import streamlit as st
import subprocess
import re

# Function to scan directories using Gobuster
def scan_directories(target_ip, wordlist, extensions, threads):
    target_url = f"http://{target_ip}"
    gobuster_command = f"gobuster dir -w {wordlist} -x {extensions} -t {threads} -u {target_url}"
    try:
        output = subprocess.check_output(gobuster_command, shell=True, text=True)
        return output
    except subprocess.CalledProcessError:
        return "Error running Gobuster command."

# Function to parse the output and extract directories and URLs
def parse_output(output):
    directories = []
    for line in output.splitlines():
        if re.search(r'\[--> http://', line):
            directories.append(line.strip())
    return directories

# Streamlit app
def dir_scan():
    #st.title("Directory Scanner using IP")

    # Input for the IP address
    ip_address = st.text_input("Enter the IP address:")

    # Input for the wordlist
    wordlist = st.text_input("Enter the wordlist path (e.g., /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt):")

    # Input for the extensions
    extensions = st.text_input("Enter the extensions to scan for (e.g., php,html)(Optional):")

    # Input for the number of threads
    threads = st.number_input("Enter the number of threads(Optional):", value=100)

    if st.button("Scan"):
        if ip_address:
            st.write(f"Scanning {ip_address}...")
            output = scan_directories(ip_address, wordlist, extensions, threads)
            if output:
                directories = parse_output(output)
                if directories:
                    st.success("Directory scan results:")
                    for directory in directories:
                        st.write(directory)
                else:
                    st.info("No directories found.")
            else:
                st.info("No directories found.")
        else:
            st.warning("Please enter an IP address.")
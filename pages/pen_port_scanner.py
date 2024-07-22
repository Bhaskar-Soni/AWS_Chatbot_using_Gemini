import streamlit as st
import nmap
import urllib.parse
import socket

# Function to scan ports using Nmap
def scan_ports(target_ip, ports):
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments=f'-p {ports} -T4')
    open_ports = []
    for host in nm.all_hosts():
        st.write(f"Scanning host: {host}")
        for proto in nm[host].all_protocols():
            st.write(f"Protocol: {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                port_state = nm[host][proto][port]['state']
                st.write(f"Port: {port}, State: {port_state}")
                if port_state == 'open':
                    open_ports.append(f"{port}/{proto}")
    return open_ports

# Function to get IP address from URL
def get_ip_from_url(url):
    parsed_uri = urllib.parse.urlparse(url)
    domain = parsed_uri.netloc if parsed_uri.netloc else parsed_uri.path
    try:
        target_ip = socket.gethostbyname(domain)
        return target_ip
    except socket.gaierror:
        return None

# Streamlit app
def port_scan():
    #st.subheader("Port Scanner")

    # Input for the URL
    url = st.text_input("Enter the IP/URL:")

    # Input for the port range or specific ports
    port_input = st.text_input("Enter port range (e.g., 1-65535) or list of ports (e.g., 80,8080,22):")

    if st.button("Scan"):
        if url and port_input:
            target_ip = get_ip_from_url(url)
            if target_ip:
                st.write(f"Resolved IP address: {target_ip}")
                st.write(f"Scanning {target_ip}...")
                
                # Determine if the input is a range or list
                if '-' in port_input:
                    ports = port_input.strip()
                else:
                    ports = ','.join([port.strip() for port in port_input.split(',')])
                
                open_ports = scan_ports(target_ip, ports)
                if open_ports:
                    st.success("Open ports:")
                    for port in open_ports:
                        st.write(port)
                else:
                    st.info("No open ports found.")
            else:
                st.error("Failed to resolve IP address from URL.")
        else:
            st.warning("Please enter a URL and port range or list of ports.")

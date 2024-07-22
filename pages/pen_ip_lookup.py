import streamlit as st
from ipwhois import IPWhois
import requests

def perform_ipwhois_lookup(ip):
    try:
        ip_info = IPWhois(ip)
        ip_details = ip_info.lookup_rdap()
        return ip_details
    except Exception as e:
        return {"error": str(e)}

def get_ipinfo(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Failed to fetch IPinfo: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def ip_lookup_app():

    input_ip = st.text_input("Enter the IP Address to lookup:")

    if st.button("Lookup"):
        ip_details = perform_ipwhois_lookup(input_ip)
        
        if "error" in ip_details:
            st.error(f"IPWhois Error: {ip_details['error']}")
        else:
            st.subheader("IPWhois Details:")
            st.json(ip_details)
            
            st.subheader("Extended IP Information (from IPinfo):")
            ipinfo_data = get_ipinfo(input_ip)
            
            if "error" in ipinfo_data:
                st.error(f"IPinfo Error: {ipinfo_data['error']}")
            else:
                st.json(ipinfo_data)

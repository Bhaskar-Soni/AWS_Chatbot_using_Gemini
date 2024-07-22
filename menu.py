import streamlit as st
import toml

# Path to the config file
config_file_path = '.streamlit/config.toml'

# Function to load the current theme from the config file
def load_theme():
    with open(config_file_path, 'r') as file:
        config = toml.load(file)
    return config['theme']['base'] == 'dark'

# Function to update the theme in the config file
def update_theme(dark_mode):
    with open(config_file_path, 'r') as file:
        config = toml.load(file)

    if dark_mode:
        config['theme']['base'] = 'dark'
        config['theme']['primaryColor'] = '#F63366'
        config['theme']['backgroundColor'] = 'black'
        config['theme']['textColor'] = '#ffffff'
    else:
        config['theme']['base'] = 'light'
        config['theme']['primaryColor'] = '#7792E3'
        config['theme']['backgroundColor'] = 'white'
        config['theme']['textColor'] = '#262730'

    with open(config_file_path, 'w') as file:
        toml.dump(config, file)

def custom_menu():
    # Add an image at the top of the menu bar
    st.sidebar.image("./aws_logo.png", use_column_width=True)
    
    # Add bold text below the image
    st.sidebar.markdown("<h2 style='text-align: center;'>AWS ChatBot</h2>", unsafe_allow_html=True)

    # Create a navigation menu
    st.sidebar.page_link("./pages/dashboard.py", label="Dashboard")
    st.sidebar.page_link("./pages/chatbot.py", label="Chat with Bot")
    st.sidebar.page_link("./pages/cost_optimization.py", label="Cost Optimization")
    st.sidebar.page_link("./pages/audit_report.py", label="Overall Audit Report")
    st.sidebar.page_link("./pages/ec2_pentest.py", label="Penetration Testing")
    st.sidebar.page_link("./pages/vuln_checker.py", label="Vulnerability Assessment")
    st.sidebar.page_link("./pages/about_us.py", label="About")

    if 'dark_mode' not in st.session_state:
        st.session_state.dark_mode = load_theme()

    # Toggle switch with immediate update
    dark_mode = st.sidebar.checkbox("Dark Mode", value=st.session_state.dark_mode)

    # Update theme immediately upon toggling the checkbox
    if dark_mode != st.session_state.dark_mode:
        st.session_state.dark_mode = dark_mode
        update_theme(dark_mode)
        st.rerun()

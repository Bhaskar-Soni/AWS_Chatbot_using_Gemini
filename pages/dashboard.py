import streamlit as st

st.set_page_config(page_title="Dashboard")

from menu import custom_menu
from pages.current_month_billing import current_billing
from pages.free_trial import check_free_tier
from pages.user_list import display_iam_users
from pages.running_service_count import running_services

def main():
    try:
        # Display the custom menu
        custom_menu()

        # Display the output from "Current Month Billing"
        current_billing()

        # Display the output from "AWS Free Tier Checker"
        check_free_tier()

        # Display the output from "AWS IAM Users"
        display_iam_users()

        # Display the output from "Running Service Count"
        running_services()

    except KeyboardInterrupt:
        st.warning('Execution interrupted, cleaning up...')
        # Perform any necessary cleanup actions here

if st.button("Chat with Bot"):
    st.write("Redirecting to the previous page...")
    st.switch_page("pages/chatbot.py")

if __name__ == '__main__':
    main()


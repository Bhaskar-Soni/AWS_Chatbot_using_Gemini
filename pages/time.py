import streamlit as st
from datetime import datetime
import time

# Streamlit UI
st.title("Real-Time Date and Time")

# Create a placeholder for displaying time
time_placeholder = st.empty()

# Update time continuously
while True:
    current_time = datetime.now().strftime("%H:%M:%S")
    time_placeholder.text("Current Time: " + current_time)
    time.sleep(1)  # Update every second


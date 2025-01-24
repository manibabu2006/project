import os
import streamlit as st
import mysql.connector

# Fetch credentials from environment variables
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")


# Connect to the database
try:
    conn = mysql.connector.connect(
        host="your-database-host",
        user=DB_USER,
        password=DB_PASSWORD,
        database="your-database-name"
    )
    st.success("Connected to the database successfully!")
except mysql.connector.Error as err:
    st.error(f"Error: {err}")

# Streamlit app content
st.title("Streamlit App with Secure Credentials")
st.write("This app securely fetches credentials from environment variables!")




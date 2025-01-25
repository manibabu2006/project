import streamlit as st
import mysql.connector
from mysql.connector import Error
import bcrypt
from twilio.rest import Client
import os
import time
from dotenv import load_dotenv
import streamlit.components.v1 as components
import random

st.title("User Authentication System")

# Load environment variables
load_dotenv()

account_sid = os.getenv('TWILIO_ACCOUNT_SID')
auth_token = os.getenv('TWILIO_AUTH_TOKEN')
twilio_phone_number = os.getenv('TWILIO_PHONE_NUMBER')

client = Client(account_sid, auth_token)

# MySQL Connection
def create_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
        if connection.is_connected():
            db_info = connection.get_server_info()
            st.write(f"Connected to MySQL Server version {db_info}")
            return connection
    except Error as e:
        st.error(f"Database connection error: {e}")
        return None

connection = create_connection()

# Helper: Generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

otp_store = {}

# Login
def login(username, password):
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            st.write("Login successful!")
            with open("pages/website.html", 'r') as f:
                html_data = f.read()
                st.markdown(html_data, unsafe_allow_html=True)
        else:
            st.write("Invalid username or password")
    else:
        st.write("No database connection available")

# Register
def register(username, password, mobile):
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            st.write("Username already exists")
        else:
            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            cursor.execute("INSERT INTO users (username, password, mobile) VALUES (%s, %s, %s)", (username, hashed_pw, mobile))
            connection.commit()
            st.write("Registration successful! You can now log in.")
    else:
        st.write("No database connection available")

# Change Password
def change_password(username, current_pw, new_pw):
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(current_pw.encode(), user['password'].encode()):
            hashed_pw = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_pw, username))
            connection.commit()
            st.write("Password changed successfully!")
        else:
            st.write("Invalid current password")
    else:
        st.write("No database connection available")

# Forgot Password
def forgot_password(username):
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user:
            # Send OTP to user for password reset
            send_otp(username)  # Ensure you have a send_otp function that works as expected
            st.write("OTP sent to your registered mobile number")
        else:
            st.write("User not found")
    else:
        st.write("No database connection available")


# Streamlit interface
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Login", "Register", "Change Password","Forgot Password"])

if page == "Login":
    st.header("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        login(username, password)

elif page == "Register":
    st.header("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    mobile = st.text_input("Mobile")
    if st.button("Register"):
        try:
            register(username, password, mobile)
            st.success("Registration successful")
        except Exception as e:
            st.error(f"Registration failed: {e}")

elif page == "Change Password":
    st.header("Change Password")
    username = st.text_input("Username")
    current_pw = st.text_input("Current Password", type="password")
    new_pw = st.text_input("New Password", type="password")
    if st.button("Change Password"):
        try:
            change_password(username, current_pw, new_pw)
            st.success("Password changed successfully")
        except Exception as e:
            st.error(f"Password change failed: {e}")

elif page == "Forgot Password":
    st.header("Forgot Password")
    with st.form(key='forgot_password_form'):
        username = st.text_input('Registration Number', key='username')
        mobile = st.text_input('Mobile Number', placeholder='Enter your mobile number', key='mobile')
        submit_otp = st.form_submit_button('Send OTP')
    if submit_otp:
        try:
            send_otp(username, mobile)
            st.success('OTP sent successfully')
        except Exception as e:
            st.error(f"Failed to send OTP: {e}")

elif page == "Verify OTP":
    st.header("Verify OTP")
    username = st.text_input("Username")
    otp = st.text_input("OTP")
    if st.button("Verify OTP"):
        try:
            verify_otp(username, otp)
            st.success("OTP verified successfully")
        except Exception as e:
            st.error(f"OTP verification failed: {e}")

elif page == "Change Password":
    st.header("Change Password")
    username = st.text_input("Username")
    current_pw = st.text_input("Current Password", type="password")
    new_pw = st.text_input("New Password", type="password")
    if st.button("Change Password"):
        try:
            change_password(username, current_pw, new_pw)
            st.success("Password changed successfully")
        except Exception as e:
            st.error(f"Password change failed: {e}")

    
# Close connection
def close_connection(connection):
    if connection and connection.is_connected():
        connection.close()
        st.write("MySQL connection is closed")

st.sidebar.text("")
if st.sidebar.button("Logout"):
    close_connection(connection)
    st.write("Logout successful")

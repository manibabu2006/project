import streamlit as st
import bcrypt
from twilio.rest import Client
import os
import time
from dotenv import load_dotenv
import random
from mysql.connector.pooling import MySQLConnectionPool
from mysql.connector import Error

# Load environment variables
load_dotenv()

# Database configuration
db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME')
}

# MySQL connection pool
connection_pool = MySQLConnectionPool(pool_name="mypool", pool_size=5, **db_config)

# Twilio setup
account_sid = os.getenv('TWILIO_ACCOUNT_SID')
auth_token = os.getenv('TWILIO_AUTH_TOKEN')
twilio_phone_number = os.getenv('TWILIO_PHONE_NUMBER')
client = Client(account_sid, auth_token)

# OTP storage
otp_store = {}

# Helper: Generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Database connection
def get_connection():
    try:
        connection = connection_pool.get_connection()
        return connection
    except Error as e:
        st.error(f"Database connection error: {e}")
        return None

# Helper: Execute query
def execute_query(query, params=None, fetchone=False):
    connection = get_connection()
    if not connection:
        return None
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params or ())
        if fetchone:
            result = cursor.fetchone()
        else:
            result = cursor.fetchall()
        connection.commit()
        return result
    except Error as e:
        st.error(f"Database error: {e}")
    finally:
        if connection.is_connected():
            connection.close()

# Login function
def login(username, password):
    query = "SELECT * FROM users WHERE username = %s"
    user = execute_query(query, (username,), fetchone=True)
    if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
        st.success("Login successful!")
        with open("pages/website.html", 'r') as f:
                html_data = f.read()
                st.components.v1.html(html_data, height=800, scrolling=True)
    else:
        st.error("Invalid username or password")

# Registration function
def register(username, password, mobile):
    query = "SELECT * FROM users WHERE username = %s"
    existing_user = execute_query(query, (username,), fetchone=True)
    if existing_user:
        st.error("Username already exists")
    else:
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        insert_query = "INSERT INTO users (username, password, mobile) VALUES (%s, %s, %s)"
        execute_query(insert_query, (username, hashed_pw, mobile))
        st.success("Registration successful! You can now log in.")

# Change password
def change_password(username, current_pw, new_pw):
    query = "SELECT * FROM users WHERE username = %s"
    user = execute_query(query, (username,), fetchone=True)
    if user and bcrypt.checkpw(current_pw.encode(), user['password'].encode()):
        hashed_pw = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
        update_query = "UPDATE users SET password = %s WHERE username = %s"
        execute_query(update_query, (hashed_pw, username))
        st.success("Password changed successfully!")
    else:
        st.error("Invalid current password")

# Forgot password: Send OTP
def send_otp(username, mobile):
    otp = generate_otp()
    otp_store[username] = {'otp': otp, 'timestamp': time.time()}
    try:
        message = client.messages.create(
            body=f"Your OTP is: {otp}",
            from_=twilio_phone_number,
            to=mobile
        )
        st.success(f"OTP sent to {mobile}")
    except Exception as e:
        st.error(f"Failed to send OTP: {e}")

# Verify OTP
def verify_otp(username, otp):
    if username in otp_store:
        saved_otp = otp_store[username]['otp']
        timestamp = otp_store[username]['timestamp']
        if otp == saved_otp and time.time() - timestamp < 300:
            st.success("OTP verified successfully!")
            del otp_store[username]
        else:
            st.error("Invalid or expired OTP")
    else:
        st.error("No OTP generated for this user")

# Streamlit UI
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Login", "Register", "Change Password", "Forgot Password"])

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
        register(username, password, mobile)

elif page == "Change Password":
    st.header("Change Password")
    username = st.text_input("Username")
    current_pw = st.text_input("Current Password", type="password")
    new_pw = st.text_input("New Password", type="password")
    if st.button("Change Password"):
        change_password(username, current_pw, new_pw)

elif page == "Forgot Password":
    st.header("Forgot Password")
    username = st.text_input("Username")
    mobile = st.text_input("Mobile")
    if st.button("Send OTP"):
        send_otp(username, mobile)
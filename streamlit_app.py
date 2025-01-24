import streamlit as st
import mysql.connector
import os

# Function to connect to MySQL database
def create_connection(host, user, password):
    try:
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password
        )
        return connection
    except mysql.connector.Error as err:
        st.error(f"Error: {err}")
        return None

# Streamlit UI to get user input
st.title("MySQL Connection with Streamlit")

# Get credentials from environment variables or user input
host = st.text_input("Host", "localhost")
user = st.text_input("User", "root")
password = st.text_input("Password", type="password")

# Button to connect to the database
if st.button("Connect to Database"):
    conn = create_connection(host, user, password)

    if conn:
        st.success("Connection successful!")

        # Show databases in MySQL
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES;")
        databases = cursor.fetchall()
        
        # Display the databases in a table
        st.write("Databases available:")
        st.table(databases)

        cursor.close()
        conn.close()
    else:
        st.error("Failed to connect to the database.")

# Optional: Include an additional query feature
query = st.text_area("SQL Query", "SELECT * FROM your_table LIMIT 5;")
if st.button("Run Query"):
    if conn:
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        st.write("Query results:")
        st.table(results)
        cursor.close()

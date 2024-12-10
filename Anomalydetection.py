import os
from PIL import Image
import numpy as np
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest
import tkinter as tk
from tkinter import messagebox

# Step 1: Advanced Anomaly Detection using Isolation Forest
class AnomalyDetection:
    def __init__(self):
        self.model = IsolationForest(contamination=0.2)  # Assume 20% outliers indata
    
    def train_model(self, data):
        self.model.fit(data)
    
    def detect_anomaly(self, data_point):
        return self.model.predict([data_point]) == -1  # -1 means anomaly

# Step 2: Encryption of Message Using Fernet (symmetric encryption)
def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message.encode()).decode()

# Step 3: Encode message using LSB with Encryption
def encode_message(image_path, message, encryption_key):
    try:
        img = Image.open(image_path)
        img = img.convert('RGB')  # Ensure it's in RGB mode
        pixels = np.array(img)

        # Encrypt the message
        encrypted_message = encrypt_message(message, encryption_key)
        binary_message = ''.join(format(ord(c), '08b') for c in encrypted_message)
        binary_message += '1111111111111110'  # EOF marker

        if len(binary_message) > pixels.size:
            raise ValueError("Message is too large to fit in this image.")

        pixel_index = 0
        for bit in binary_message:
            x = pixel_index // pixels.shape[1]  # X coordinate
            y = pixel_index % pixels.shape[1]   # Y coordinate
            pixel = list(pixels[x, y])
            pixel[0] = (pixel[0] & 0xFE) | int(bit)  # LSB encoding
            pixels[x, y] = tuple(pixel)
            pixel_index += 1

        # Save the modified image
        encoded_img = Image.fromarray(pixels)
        encoded_img.save('encoded_image.png')
        print("Message encoded and saved to 'encoded_image.png'.")
    
    except Exception as e:
        print(f"Error encoding message: {e}")

def decode_message(image_path, encryption_key):
    try:
        img = Image.open(image_path)
        pixels = np.array(img)

        binary_message = ""
        for pixel in pixels.reshape(-1, 3):  # Flatten the 2D image into 1D pixelarray
            binary_message += str(pixel[0] & 1)  # Extract the LSB of the Redcomponent

        eof_marker = '1111111111111110'  # EOF marker
        if eof_marker in binary_message:
            binary_message = binary_message[:binary_message.index(eof_marker)]
        else:
            print("EOF marker not found. Decoding may be incomplete orcorrupted.")
            return None

        message = ""
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i+8]
            if len(byte) == 8:  
                message += chr(int(byte, 2))  # Convert binary to string

        decrypted_message = decrypt_message(message, encryption_key)
        return decrypted_message

    except Exception as e:
        print(f"Error during message decoding: {e}")
        return None

# Step 5: Simulate and Train Anomaly Detection
def simulate_user_data():
    # Simulated login times with a clear outlier
    login_data = [[1], [2], [3], [4], [5], [6], [7], [10], [12], [13], [15], [100]]  # 100is an outlier
    model = AnomalyDetection()
    model.train_model(login_data)
    return model

# Step 6: UI Functionality for Login Check and Anomaly Detection
def check_login():
    username = entry_username.get()
    ip = entry_ip.get()
    try:
        login_time = int(entry_time.get())
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid login time.")
        return
    
    # Run anomaly detection
    if anomaly_detector.detect_anomaly([login_time]):
        messagebox.showwarning("Anomaly Detected", f"Anomaly detected for {username}: Unusual login attempt!")
        
        alert_message = f"Anomaly Detected for {username}: Unusual login from IP {ip} at {login_time}."
        encode_message('logo.png', alert_message, encryption_key)  # Ensure 'logo.png' exists
        decoded_message = decode_message('encoded_image.png', encryption_key)
        
        if decoded_message:
            messagebox.showinfo("Decoded Message", f"Decoded and Decrypted Message: {decoded_message}")
        else:
            messagebox.showerror("Decoding Error", "Failed to decode or decrypt the message.")
    else:
        messagebox.showinfo("No Anomaly", f"No anomaly detected for {username}.")
# Initialize Tkinter window
root = tk.Tk()
root.title("Anomaly Detection and Encryption")
root.geometry("400x400")

# Add labels and entry widgets
tk.Label(root, text="Username").pack(pady=5)
entry_username = tk.Entry(root)
entry_username.pack(pady=5)

tk.Label(root, text="IP Address").pack(pady=5)
entry_ip = tk.Entry(root)
entry_ip.pack(pady=5)

tk.Label(root, text="Login Time").pack(pady=5)
entry_time = tk.Entry(root)
entry_time.pack(pady=5)

# Add button to check login
button_check = tk.Button(root, text="Check Login", command=check_login)
button_check.pack(pady=20)

# Initialize anomaly detector and encryption key
anomaly_detector = simulate_user_data()
encryption_key = generate_key()

root.mainloop()
database_connection.py
import mysql.connector
from mysql.connector import Error
import bcrypt
import tkinter as tk
from tkinter import messagebox

# Database connection
def get_user_credentials(username):
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root", 
            password="your_password_here",
            database="login_system"
        )

        if connection.is_connected():
            cursor = connection.cursor()
            query = "SELECT username, password FROM users WHERE username= %s"
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            if result:
                return result
            else:
                return None
    except Error as e:
        print("Error:", e)
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Password checking function
def check_password(input_password, stored_hash):
    return bcrypt.checkpw(input_password.encode(), stored_hash.encode())

# Login check
def check_login():
    username = entry_username.get()
    input_password = entry_password.get()

    # Retrieve stored credentials from the database
    credentials = get_user_credentials(username)

    if credentials:
        stored_username, stored_hash = credentials
        if check_password(input_password, stored_hash):
            messagebox.showinfo("Login Success", f"Welcome{stored_username}!")
        else:
            messagebox.showerror("Login Failed", "Incorrect password.")
    else:
        messagebox.showerror("Login Failed", "User not found.")

# GUI setup
root = tk.Tk()
root.title("Login")

tk.Label(root, text="Username").pack(pady=5)
entry_username = tk.Entry(root)
entry_username.pack(pady=5)

tk.Label(root, text="Password").pack(pady=5)
entry_password = tk.Entry(root, show="*")
entry_password.pack(pady=5)

button_login = tk.Button(root, text="Login", command=check_login)
button_login.pack(pady=20)

root.mainloop()



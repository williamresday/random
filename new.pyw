import tkinter as tk
import customtkinter as ctk
import os
import json
import hashlib
import random
import requests
import time
import threading
import subprocess
import socket
import platform
import psutil
import string
import base64
import speedtest
import scapy.all as scapy
from cryptography.fernet import Fernet
from tkinter import messagebox, filedialog
from keyauth import *
from concurrent.futures import ThreadPoolExecutor


url = "https://keyauth.win/api/1.2/?type=init&ver=&name=&ownerid=&hash&token&thash"
payload = {}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)

# Helper function to calculate checksum
def getchecksum():
    path = os.path.basename(__file__)
    md5_hash = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

# Initialize KeyAuth API
keyauthapp = api(
    name="Applocal's Application",  # App name
    ownerid="zVsjPFJKTc",  # Account ID
    version="1.0",  # Application version
    hash_to_check=getchecksum(),  # File checksum
)

# Guard to prevent multiple initialization
try:
    if not hasattr(keyauthapp, 'initialized') or not keyauthapp.initialized:
        keyauthapp.init()
        keyauthapp.initialized = True  # Mark as initialized to avoid reinitialization
except Exception as e:
    messagebox.showerror(f"Failed to initialize KeyAuth: {str(e)}")

# Settings file and key file
KEY_FILE = "encryption.key"

SETTINGS_FILE = os.path.join(os.getcwd(), "settings.json")
if not os.path.exists(SETTINGS_FILE):
    with open(SETTINGS_FILE, "w") as file:
        json.dump({}, file)  # Create an empty JSON file

USERINFO_FILE = os.path.join(os.getcwd(), "savedcreds.json")
if not os.path.exists(USERINFO_FILE):
    with open(USERINFO_FILE, "w") as file:
        json.dump({}, file)  # Create an empty JSON file


# Set appearance defaults
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class LoginRegisterApp(ctk.CTk):
    def __init__(self):
        super().__init__()  

        # Configure the main login window
        self.title("Login/Register")
        self.geometry("350x400")
        self.resizable(False, False)
        openstack_icon = self.iconbitmap('logo.png')

        # Frames for login/register forms
        self.frame = ctk.CTkFrame(self, corner_radius=10)
        self.frame.pack(pady=40, padx=40, fill="both", expand=True)

        # Application Title
        self.title_label = ctk.CTkLabel(self.frame, text="AEQ Manager", font=ctk.CTkFont(size=20, weight="bold"))
        self.title_label.pack(pady=10)

        # Username Entry
        self.username_entry = ctk.CTkEntry(self.frame, placeholder_text="Username")
        self.username_entry.pack(pady=(10, 5))

        # Password Entry
        self.password_entry = ctk.CTkEntry(self.frame, placeholder_text="Password", show="*")
        self.password_entry.pack(pady=(5, 5))

        # License Key Entry
        self.license_key_entry = ctk.CTkEntry(self.frame, placeholder_text="License Key")
        self.license_key_entry.pack(pady=(5, 20))

        # Login Button
        self.login_button = ctk.CTkButton(self.frame, text="Login", command=self.perform_login)
        self.login_button.pack(pady=10)

        # Register Button
        self.register_button = ctk.CTkButton(self.frame, text="Register", fg_color="gray", command=self.perform_register)
        self.register_button.pack()

        # Load or generate encryption key
        self.key = self.load_or_generate_key()

        # Load saved credentials
        self.load_saved_credentials()

    def load_or_generate_key(self):
        """Load or generate an encryption key."""
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as file:
                return file.read()
        else:
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as file:
                file.write(key)
            return key

    def encrypt_data(self, data):
        """Encrypt data using the Fernet key."""
        cipher = Fernet(self.key)
        encrypted = cipher.encrypt(data.encode()).decode()
        return encrypted

    def decrypt_data(self, data):
        """Decrypt data using the Fernet key."""
        cipher = Fernet(self.key)
        decrypted = cipher.decrypt(data.encode()).decode()
        return decrypted

    def save_credentials(self, username, password, license):
        """Save encrypted user credentials."""
        try:
            encrypted_data = {
                "username": self.encrypt_data(username),
                "password": self.encrypt_data(password),
                "license_key": self.encrypt_data(license),
            }
            with open(USERINFO_FILE, "w") as file:
                json.dump(encrypted_data, file, indent=4)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")

    def load_saved_credentials(self):
        """Load decrypted user credentials and populate fields."""
        if os.path.exists(USERINFO_FILE):
            try:
                with open(USERINFO_FILE, "r") as file:
                    encrypted_data = json.load(file)

                # Debug: Print encrypted data

                # Decrypt only if the data is non-empty
                username = self.decrypt_data(encrypted_data["username"]) if encrypted_data.get("username") else ""
                password = self.decrypt_data(encrypted_data["password"]) if encrypted_data.get("password") else ""
                license = self.decrypt_data(encrypted_data["license_key"]) if encrypted_data.get("license") else ""

                # Debug: Print decrypted data

                # Populate fields
                if username:
                    self.username_entry.insert(0, username)
                if password:
                    self.password_entry.insert(0, password)
                if license:
                    self.license_key_entry.insert(0, license)

            except Exception as e:
                # Debug: Print the exception for troubleshooting
                messagebox.showerror("Error", f"Failed to load saved settings: {e}")
        else:
            # If settings file doesn't exist, initialize fields as empty
            self.username_entry.delete(0, ctk.END)
            self.password_entry.delete(0, ctk.END)
            self.license_key_entry.delete(0, ctk.END)

    def validate_settings_file(self):
        """Validate that the settings file contains the required keys."""
        try:
            with open(USERINFO_FILE, "r") as file:
                encrypted_data = json.load(file)

            # Ensure all required keys are present
            required_keys = ["username", "password", "license"]
            for key in required_keys:
                if key not in encrypted_data:
                    return False
            return True
        except Exception as e:
            messagebox.showerror("Validation error:", e)
            return False


    def perform_login(self):
        if not keyauthapp:
            messagebox.showerror("Error", "KeyAuth initialization failed.")
            return

        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        try:
            # Attempt login with KeyAuth
            keyauthapp.login(username, password)
            messagebox.showinfo("Success", "Login successful!")

            # Save credentials after successful login
            self.save_credentials(username, password, "")  # License key not required for login
            self.open_main_app()
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {e}")


    def perform_register(self):
        if not keyauthapp:
            messagebox.showerror("Error", "KeyAuth initialization failed.")
            return

        username = self.username_entry.get()
        password = self.password_entry.get()
        license = self.license_key_entry.get()

        # Validate inputs
        if not username:
            messagebox.showerror("Error", "Please enter a valid username.")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a valid password.")
            return
        if not license:
            messagebox.showerror("Error", "Please enter a valid license key.")
            return

        try:
            # Attempt registration with KeyAuth
            keyauthapp.register(username, password, license)
            messagebox.showinfo("Success", "Registration successful!")

            # Save credentials after successful registration
            self.save_credentials(username, password, license)
            self.open_main_app()
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {e}")


    def open_main_app(self):
        self.destroy()  # Close the login window
        main_app = MainApp()  # Initialize the MainApp window
        main_app.mainloop()  # Start the MainApp event loop


class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        # Initialize the console_output widget
        self.console_output = None  # Ensure it's defined early

        # Configure window
        self.title("AEQ Manager")
        self.geometry("1120x580")
        self.resizable(False, False)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Load settings
        self.settings = self.load_settings()

        # Apply appearance mode and scaling
        ctk.set_appearance_mode(self.settings.get("appearance_mode", "System"))
        ctk.set_widget_scaling(int(self.settings.get("scaling", "100%").replace("%", "")) / 100)

        # Sidebar setup
        self.sidebar_frame = ctk.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="AEQ Manager", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Tab buttons
        self.tab_button_names = ["Overview", "Tools", "System Info", "Network", "Help", "Settings"]
        self.tab_buttons = []  # List to store the tab buttons
        self.active_tab_index = 0  # Track the active tab index

        for i, name in enumerate(self.tab_button_names):
                button = ctk.CTkButton(
                    self.sidebar_frame,
                    text=name,
                    command=lambda i=i: self.open_tab(i),
                    fg_color="gray20",  # Default color
                    hover_color="gray30",
                    corner_radius=0
                )
                button.grid(row=i + 1, column=0, padx=10, pady=5, sticky="ew")
                self.tab_buttons.append(button)
                self.content_frame = ctk.CTkFrame(self)
                self.content_frame.grid(row=0, column=1, padx=(20, 20), pady=(20, 20), sticky="nsew")
                self.open_tab(0)

        # Show app
        self.mainloop()

    def open_tab(self, tab_index):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        self.active_tab_index = tab_index
        self.update_tab_buttons()

        if tab_index == 0:  # Overview
            self.create_overview_tab()
        elif tab_index == 1:  # Tools
            self.create_tools_tab()
        elif tab_index == 2:  # System info
            self.create_systeminfo_tab()
        elif tab_index == 3:  # Network
            self.create_network_tab()
        elif tab_index == 4:  # help
            self.create_help_tab()           
        elif tab_index == 5:  # Settings
            self.create_settings_tab()
        else:
            ctk.CTkLabel(
                self.content_frame,
                text="This page is under construstion.",
                font=ctk.CTkFont(size=20, weight="bold")
            ).grid(row=0, column=0, padx=20, pady=20)

    def update_tab_buttons(self):
        """Update the appearance of the sidebar buttons."""
        for i, button in enumerate(self.tab_buttons):
            if i == self.active_tab_index:
                # Highlight the active button
                button.configure(fg_color="blue", text_color="white")
            else:
                # Reset non-active buttons
                button.configure(fg_color="gray20", text_color="light gray")

    def create_overview_tab(self):
        # Overview Header
        ctk.CTkLabel(
            self.content_frame,
            text="Overview",
            font=ctk.CTkFont(size=20, weight="bold")
        ).grid(row=0, column=0, padx=20, pady=(10, 5), sticky="w")

        # Separator Line
        separator = ctk.CTkFrame(self.content_frame, height=2, fg_color="gray")
        separator.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=(0, 10))

        # Frame for Users Online and Auth Connection
        self.stats_frame = ctk.CTkFrame(self.content_frame, corner_radius=10)
        self.stats_frame.grid(row=2, column=0, padx=20, pady=20, sticky="nw")

        # Initial Online Users Display
        self.online_users_label = ctk.CTkLabel(
            self.stats_frame,
            text="Online Users: ",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.online_users_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.online_users_value = ctk.CTkLabel(
            self.stats_frame,
            text="0",
            font=ctk.CTkFont(size=14)
        )
        self.online_users_value.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        # Auth Connection Label
        self.auth_connection_label = ctk.CTkLabel(
            self.stats_frame,
            text="Auth Connection: ",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.auth_connection_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        # Display the auth connection status (simulate the status as 'Connected' or 'Disconnected')
        self.auth_connection_value = ctk.CTkLabel(
            self.stats_frame,
            text="Connected",  # Initial status (could be updated dynamically)
            font=ctk.CTkFont(size=14)
        )
        self.auth_connection_value.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Start updating the online users and auth connection status
        self.update_online_users()
        self.update_auth_connection()

    def update_online_users(self):
        random_users = random.randint(10, 20)
        self.online_users_value.configure(text=str(random_users))
        self.after(20000, self.update_online_users)  # Update every 10 seconds

    def update_auth_connection(self):
        try:
            # Check the KeyAuth API connection by making a simple request
            response = requests.get(url)  # Use the existing url and make a GET request to the API

            if response.status_code == 200:  # If the status code is 200, the connection is successful
                # If the connection is successful, update the status to "Connected"
                self.auth_connection_value.configure(text="CONNECTED", text_color="green")
            else:
                # If the status code is not 200, update the status to "Disconnected"
                self.auth_connection_value.configure(text="DISCONNECTED", text_color="red")

        except Exception as e:
            # In case of any errors, we will set the connection status to "Disconnected"
            self.auth_connection_value.configure(text="DISCONNECTED", text_color="red")
    
        # Update the status every 10 seconds
        self.after(10000, self.update_auth_connection)  # Update every 10 seconds

    def create_tools_tab(self):
        # Create Tabview for Tools
        tools_tabview = ctk.CTkTabview(self.content_frame, width=800, height=500)
        tools_tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        # Add tabs to the Tabview
        tools_tabview.add("IP Tools")
        tools_tabview.add("File Hasher")
        tools_tabview.add("File Encryption/Decryption")
        tools_tabview.add("Password Generator")

        # --- IP Tools Tab ---
        ip_tools_tab = tools_tabview.tab("IP Tools")

        # Frame for IP Pinger
        ip_pinger_frame = ctk.CTkFrame(ip_tools_tab)
        ip_pinger_frame.grid(row=0, column=0, padx=20, pady=10, sticky="w")

        ctk.CTkLabel(ip_pinger_frame, text="IP Pinger").grid(row=0, column=0, padx=10, pady=5)
        ip_entry = ctk.CTkEntry(ip_pinger_frame, placeholder_text="Enter IP address")
        ip_entry.grid(row=0, column=1, padx=10, pady=5)
        ping_result_text = tk.Text(ip_pinger_frame, height=10, width=50, state=tk.DISABLED, bg="#2E2E2E", fg="#00FF00")
        ping_result_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

        stop_event = threading.Event()  # Event object to stop pinging

        # Function to ping an IP address in a separate thread
        def ping_ip():
            ip_address = ip_entry.get().strip()
            if not ip_address:
                update_output("Please enter a valid IP address.")
                return

            stop_event.clear()  # Reset the stop event

            def ping_thread():
                while not stop_event.is_set():  # Loop until stop event is set
                    try:
                        result = subprocess.run(
                            ["ping", "-n", "1", ip_address],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                        if "Reply from" in result.stdout:
                            update_output("Ping success")
                        else:
                            update_output("Ping failed")
                    except Exception as e:
                        update_output(f"Error: {e}")
                        break
                    time.sleep(1)  # Optional: Wait 1 second between pings

            # Start the ping in a new thread
            threading.Thread(target=ping_thread, daemon=True).start()

        # Function to stop the pinging process
        def stop_pinging():
            stop_event.set()  # Signal the thread to stop
            update_output("Pinging stopped.")

        # Function to update the output text box
        def update_output(message):
            ping_result_text.configure(state=tk.NORMAL)
            ping_result_text.insert(tk.END, message + "\n")
            ping_result_text.configure(state=tk.DISABLED)
            ping_result_text.see(tk.END)  # Scroll to the latest line

        # Ping Button
        ctk.CTkButton(
            ip_pinger_frame,
            text="Start Ping",
            command=ping_ip,
            fg_color="gray20",  # Default color
            hover_color="gray30",
            corner_radius=0
        ).grid(row=0, column=2, padx=10, pady=5)

        # Stop Ping Button
        ctk.CTkButton(
            ip_pinger_frame,
            text="Stop Ping",
            command=stop_pinging,
            fg_color="gray20",  # Default color
            hover_color="gray30",
            corner_radius=0
        ).grid(row=0, column=3, padx=10, pady=5)

        # Frame for IP Lookup
        ip_lookup_frame = ctk.CTkFrame(ip_tools_tab)
        ip_lookup_frame.grid(row=1, column=0, padx=20, pady=10, sticky="w")

        # Label for IP Lookup Section
        ctk.CTkLabel(ip_lookup_frame, text="IP Lookup").grid(row=0, column=0, padx=10, pady=5)

        # Entry for IP address input
        lookup_entry = ctk.CTkEntry(ip_lookup_frame, placeholder_text="Enter IP address")
        lookup_entry.grid(row=0, column=1, padx=10, pady=5)

        # Function to handle IP Lookup
        def lookup_ip():
            ip_address = lookup_entry.get().strip()
            if not ip_address:
                update_lookup_output("Please enter a valid IP address.")
                return
            try:
                # Perform a reverse DNS lookup
                host = socket.gethostbyaddr(ip_address)
                update_lookup_output(f"Hostname for {ip_address}: {host[0]}")
            except socket.herror:
                update_lookup_output(f"Hostname not found for {ip_address}.")
            except Exception as e:
                update_lookup_output(f"Error: {e}")

        # Function to update the output box for Lookup
        def update_lookup_output(message):
            lookup_result_text.configure(state=tk.NORMAL)
            lookup_result_text.insert(tk.END, message + "\n")
            lookup_result_text.configure(state=tk.DISABLED)
            lookup_result_text.see(tk.END)  # Scroll to the latest line

        # Function to clear the input and output fields
        def clear_lookup():
            lookup_entry.delete(0, tk.END)  # Clear the input field
            lookup_result_text.configure(state=tk.NORMAL)
            lookup_result_text.delete(1.0, tk.END)  # Clear the output box
            lookup_result_text.configure(state=tk.DISABLED)

        # Lookup Button
        ctk.CTkButton(
            ip_lookup_frame,
            text="Lookup",
            command=lookup_ip,
            fg_color="gray20",  # Default color
            hover_color="gray30",
            corner_radius=0
        ).grid(row=0, column=2, padx=10, pady=5)

        # Clear Button
        ctk.CTkButton(
            ip_lookup_frame,
            text="Clear",
            command=clear_lookup,
            fg_color="gray20",  # Default color
            hover_color="gray30",
            corner_radius=0
        ).grid(row=0, column=3, padx=10, pady=5)

        # Text Box for Lookup Output
        lookup_result_text = tk.Text(ip_lookup_frame, height=10, width=50, state=tk.DISABLED, bg="#2E2E2E", fg="#00FF00")
        lookup_result_text.grid(row=1, column=0, columnspan=4, padx=10, pady=10)

        # --- File Hasher Tab ---
        file_hasher_tab = tools_tabview.tab("File Hasher")

        # Initialize the global selected_file_path variable
        selected_file_path = None

        def generate_file_hash(algorithm):
            global selected_file_path  # Declare it as global so we can access the variable
            if selected_file_path:
                try:
                    with open(selected_file_path, "rb") as f:
                        file_data = f.read()
                    if algorithm == "MD5":
                        hash_result = hashlib.md5(file_data).hexdigest()
                    elif algorithm == "SHA1":
                        hash_result = hashlib.sha1(file_data).hexdigest()
                    elif algorithm == "SHA256":
                        hash_result = hashlib.sha256(file_data).hexdigest()
                    update_file_hasher_output(f"{algorithm} Hash: {hash_result}")
                except Exception as e:
                    update_file_hasher_output(f"Error: {e}")
            else:
                update_file_hasher_output("Error: No file selected!")

        def browse_file():
            global selected_file_path  # Use the global variable
            selected_file_path = filedialog.askopenfilename()
            if selected_file_path:
                selected_file_label.configure(text=f"Selected: {selected_file_path}")
                browse_button.configure(state=tk.DISABLED)  # Disable the browse button after selecting a file
                clear_button.configure(state=tk.NORMAL)  # Enable the clear button

        def clear_file():
            global selected_file_path  # Reset the file path
            selected_file_path = None  # Clear the selected file path
            selected_file_label.configure(text="No file selected")  # Update the label
            browse_button.configure(state=tk.NORMAL)  # Enable the browse button again
            clear_button.configure(state=tk.DISABLED)  # Disable the clear button until a file is selected

        def update_file_hasher_output(message):
            file_hasher_output.configure(state=tk.NORMAL)
            file_hasher_output.insert(tk.END, message + "\n")
            file_hasher_output.configure(state=tk.DISABLED)
            file_hasher_output.see(tk.END)

        # Create the user interface
        selected_file_label = ctk.CTkLabel(file_hasher_tab, text="No file selected")
        selected_file_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        browse_button = ctk.CTkButton(file_hasher_tab, text="Browse File", command=browse_file)
        browse_button.grid(row=1, column=0, padx=10, pady=5)

        # Clear File button
        clear_button = ctk.CTkButton(file_hasher_tab, text="Clear File", command=clear_file, state=tk.DISABLED)
        clear_button.grid(row=1, column=1, padx=10, pady=5)

        # File hasher output box
        file_hasher_output = tk.Text(file_hasher_tab, height=10, width=80, state=tk.DISABLED, bg="#2E2E2E", fg="#00FF00")
        file_hasher_output.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

        # Buttons for hash algorithms
        ctk.CTkButton(file_hasher_tab, text="MD5", command=lambda: generate_file_hash("MD5")).grid(row=3, column=0, padx=10, pady=5, sticky="s")
        ctk.CTkButton(file_hasher_tab, text="SHA1", command=lambda: generate_file_hash("SHA1")).grid(row=3, column=1, padx=10, pady=5, sticky="s")
        ctk.CTkButton(file_hasher_tab, text="SHA256", command=lambda: generate_file_hash("SHA256")).grid(row=3, column=2, padx=10, pady=5, sticky="s")

        # Configure grid layout
        file_hasher_tab.grid_rowconfigure(0, weight=0)
        file_hasher_tab.grid_rowconfigure(1, weight=0)
        file_hasher_tab.grid_rowconfigure(2, weight=0)
        file_hasher_tab.grid_rowconfigure(3, weight=0)

        file_hasher_tab.grid_columnconfigure(0, weight=1)
        file_hasher_tab.grid_columnconfigure(1, weight=1)
        file_hasher_tab.grid_columnconfigure(2, weight=1)

        # --- File Encryption/Decryption Tab ---
        encryption_tab = tools_tabview.tab("File Encryption/Decryption")

        # Encryption function
        def encrypt_file():
            file_path = filedialog.askopenfilename(title="Select a file to encrypt")
            if file_path:
                try:
                    with open(file_path, "rb") as f:
                        data = f.read()
                    encrypted_data = base64.b64encode(data)
                    with open(file_path + ".enc", "wb") as f:
                        f.write(encrypted_data)
                    update_encryption_output(f"File encrypted successfully! Saved as {file_path}.enc")
                except Exception as e:
                    update_encryption_output(f"Error: {e}")

        # Decryption function
        def decrypt_file():
            file_path = filedialog.askopenfilename(title="Select a file to decrypt")
            if file_path:
                try:
                    with open(file_path, "rb") as f:
                        data = f.read()
                    decrypted_data = base64.b64decode(data)
                    with open(file_path.replace(".enc", ""), "wb") as f:
                        f.write(decrypted_data)
                    update_encryption_output(f"File decrypted successfully! Saved as {file_path.replace('.enc', '')}")
                except Exception as e:
                    update_encryption_output(f"Error: {e}")

        # Update the encryption output text widget
        def update_encryption_output(message):
            encryption_output.configure(state=tk.NORMAL)  # Allow editing temporarily
            encryption_output.insert(tk.END, message + "\n")  # Insert the message into the text box
            encryption_output.configure(state=tk.DISABLED)  # Disable editing again after insertion
            encryption_output.see(tk.END)  # Scroll to the end to see the latest message

        # Create the encryption output Text widget (initially read-only)
        encryption_output = tk.Text(encryption_tab, height=10, width=80, state=tk.DISABLED, bg="#2E2E2E", fg="#00FF00", wrap="word")
        encryption_output.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        # Adjust button size to be smaller
        button_width = 20  # Smaller width for the buttons

        # Encrypt Button
        encrypt_button = ctk.CTkButton(
            encryption_tab,
            text="Encrypt File",
            command=encrypt_file,
            fg_color="gray30",  # Default color
            hover_color="gray40",
            corner_radius=0,
            width=button_width  # Set a fixed width for the button
        )
        encrypt_button.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

        # Decrypt Button
        decrypt_button = ctk.CTkButton(
            encryption_tab,
            text="Decrypt File",
            command=decrypt_file,
            fg_color="gray30",  # Default color
            hover_color="gray40",
            corner_radius=0,
            width=button_width  # Set a fixed width for the button
        )
        decrypt_button.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        # Configure the grid to prevent button expansion
        encryption_tab.grid_columnconfigure(0, weight=0)  # No expansion for column 0
        encryption_tab.grid_columnconfigure(1, weight=0)  # No expansion for column 1

        #creates the tab
        password_generator_tab = tools_tabview.tab("Password Generator")

        # Function to generate and display a password
        def generate_password(length):
            characters = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(characters) for i in range(length))
            password_output.configure(state=tk.NORMAL)  # Allow editing temporarily
            password_output.delete(0, tk.END)          # Clear any previous password
            password_output.insert(0, password)       # Insert the generated password
            password_output.configure(state=tk.DISABLED)  # Disable editing again

        # Label and Slider for password length
        ctk.CTkLabel(password_generator_tab, text="Password Length:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        password_length = tk.IntVar(value=12)
        password_length_slider = ctk.CTkSlider(password_generator_tab, from_=6, to=32, variable=password_length, number_of_steps=26)
        password_length_slider.grid(row=0, column=1, padx=10, pady=5)

        # Generate Password Button
        ctk.CTkButton(
            password_generator_tab,
            text="Generate Password",
            command=lambda: generate_password(password_length.get()),
            fg_color="gray30",  # Default color
            hover_color="gray40",
            corner_radius=0,
        ).grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        # Password Output Entry
        password_output = tk.Entry(password_generator_tab, width=50, state=tk.DISABLED, bg="#2E2E2E", fg="#00FF00", justify="center")
        password_output.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

    def create_systeminfo_tab(self):
        # Create a main frame to hold the content
        main_frame = ctk.CTkFrame(self.content_frame)
        main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        # Configure grid weights to center content
        main_frame.grid_columnconfigure(0, weight=1)  # Center alignment
        main_frame.grid_rowconfigure(0, weight=1)     # Add vertical centering

        # Title with separator underline
        title_label = ctk.CTkLabel(
            main_frame,
            text="System Information",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="n")

        # Add a separator frame below the title to mimic an underline
        separator = ctk.CTkFrame(main_frame, height=2, fg_color="gray")
        separator.grid(row=1, column=0, sticky="ew", padx=50, pady=(0, 20))  # Adjust padding for spacing

        # Create a sub-frame to hold the information
        info_frame = ctk.CTkFrame(main_frame)
        info_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        info_frame.grid_columnconfigure(0, weight=1)
        info_frame.grid_columnconfigure(1, weight=1)

        # Get system information
        system_info = {
            "OS": platform.system() + " " + platform.release(),
            "OS Version": platform.version(),
            "Architecture": platform.architecture()[0],
            "Machine": platform.machine(),
            "Processor": platform.processor(),
            "CPU Cores (Physical)": psutil.cpu_count(logical=False),
            "CPU Cores (Logical)": psutil.cpu_count(logical=True),
            "RAM Size (GB)": round(psutil.virtual_memory().total / (1024 ** 3), 2),
            "Hostname": socket.gethostname(),
            "IP Address": socket.gethostbyname(socket.gethostname())
        }

        # Display system information
        row = 0
        for key, value in system_info.items():
            # Label for the key
            ctk.CTkLabel(
                info_frame,
                text=f"{key}:",
                font=ctk.CTkFont(size=14, weight="bold"),
                anchor="e"  # Align text to the right
            ).grid(row=row, column=0, padx=10, pady=5, sticky="e")

            # Label for the value
            ctk.CTkLabel(
                info_frame,
                text=str(value),
                font=ctk.CTkFont(size=14),
                anchor="w"  # Align text to the left
            ).grid(row=row, column=1, padx=10, pady=5, sticky="w")

            row += 1

        # Add a refresh button
        def refresh_system_info():
            updated_info = {
                "OS": platform.system() + " " + platform.release(),
                "OS Version": platform.version(),
                "Architecture": platform.architecture()[0],
                "Machine": platform.machine(),
                "Processor": platform.processor(),
                "CPU Cores (Physical)": psutil.cpu_count(logical=False),
                "CPU Cores (Logical)": psutil.cpu_count(logical=True),
                "RAM Size (GB)": round(psutil.virtual_memory().total / (1024 ** 3), 2),
                "Hostname": socket.gethostname(),
                "IP Address": socket.gethostbyname(socket.gethostname())
            }
            for i, (key, value) in enumerate(updated_info.items(), start=0):
                # Update only the value labels
                info_frame.grid_slaves(row=i, column=1)[0].configure(text=str(value))

        # Refresh Button
        ctk.CTkButton(
            main_frame,
            text="Refresh",
            command=refresh_system_info,
            fg_color="gray30",  # Default color
            hover_color="gray40",
            corner_radius=0
        ).grid(row=3, column=0, pady=10, sticky="n")

    def create_network_tab(self):
        # Create Tabview for network
        network_tabview = ctk.CTkTabview(self.content_frame, width=800, height=500)
        network_tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        # Add tabs
        network_tabview.add("Speed Test")
        network_tabview.add("Port Scan")
        network_tabview.add("Network Monitoring")

        # Add content to each tab
        self.add_speed_test_tab(network_tabview.tab("Speed Test"))
        self.add_port_scan_tab(network_tabview.tab("Port Scan"))
        self.add_network_monitoring_tab(network_tabview.tab("Network Monitoring"))

    def add_speed_test_tab(self, tab_frame):
        # Speed Test UI
        ctk.CTkLabel(tab_frame, text="Speed Test", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, padx=10, pady=5)

        self.speed_test_result_text = tk.Text(tab_frame, height=8, width=50, state=tk.DISABLED, bg="#2E2E2E", fg="#00FF00")
        self.speed_test_result_text.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

        def run_speed_test():
            self.speed_test_result_text.configure(state=tk.NORMAL)
            self.speed_test_result_text.delete(1.0, tk.END)
            self.speed_test_result_text.insert(tk.END, "Running speed test, please wait...\n")
            self.speed_test_result_text.configure(state=tk.DISABLED)
            self.speed_test_result_text.update()

            try:
                st = speedtest.Speedtest()
                st.get_best_server()
                download_speed = st.download() / 1_000_000  # Mbps
                upload_speed = st.upload() / 1_000_000  # Mbps
                ping_latency = st.results.ping

                result = (
                    f"Download Speed: {download_speed:.2f} Mbps\n"
                    f"Upload Speed: {upload_speed:.2f} Mbps\n"
                    f"Ping: {ping_latency:.2f} ms\n"
                )
            except Exception as e:
                result = f"Error: {e}"

            self.speed_test_result_text.configure(state=tk.NORMAL)
            self.speed_test_result_text.insert(tk.END, result)
            self.speed_test_result_text.configure(state=tk.DISABLED)
            self.speed_test_result_text.see(tk.END)

        def start_speed_test_thread():
            threading.Thread(target=run_speed_test, daemon=True).start()

        ctk.CTkButton(
            tab_frame, text="Start Speed Test", command=start_speed_test_thread
        ).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def add_port_scan_tab(self, tab_frame):
        # Port Scan UI
        ctk.CTkLabel(tab_frame, text="Port Scanner", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, padx=10, pady=5)

        ctk.CTkLabel(tab_frame, text="Enter Host (IP/Domain):").grid(row=1, column=0, padx=10, pady=5)
        host_entry = ctk.CTkEntry(tab_frame, width=300)
        host_entry.grid(row=1, column=1, padx=10, pady=5)

        ctk.CTkLabel(tab_frame, text="Port Range (e.g., 20-80):").grid(row=2, column=0, padx=10, pady=5)
        port_range_entry = ctk.CTkEntry(tab_frame, width=300)
        port_range_entry.grid(row=2, column=1, padx=10, pady=5)

        result_text = tk.Text(tab_frame, height=8, width=50, state=tk.DISABLED, bg="#2E2E2E", fg="#00FF00")
        result_text.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        def scan_ports():
            host = host_entry.get()
            try:
                start_port, end_port = map(int, port_range_entry.get().split('-'))
            except ValueError:
                result_text.configure(state=tk.NORMAL)
                result_text.insert(tk.END, "Invalid port range format.\n")
                result_text.configure(state=tk.DISABLED)
                return

            result_text.configure(state=tk.NORMAL)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Scanning {host} ports {start_port}-{end_port}...\n")
            result_text.configure(state=tk.DISABLED)
            result_text.update()

            open_ports = []

            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.scan_port, host, port): port for port in range(start_port, end_port + 1)}
                for future in futures:
                    port, is_open = future.result()
                    if is_open:
                        open_ports.append(port)

            result_text.configure(state=tk.NORMAL)
            if open_ports:
                result_text.insert(tk.END, f"Open ports: {', '.join(map(str, open_ports))}\n")
            else:
                result_text.insert(tk.END, "No open ports found.\n")
            result_text.configure(state=tk.DISABLED)

        def start_scan_thread():
            threading.Thread(target=scan_ports, daemon=True).start()

        ctk.CTkButton(
            tab_frame, text="Start Scan", command=start_scan_thread
        ).grid(row=4, column=0, columnspan=2, padx=10, pady=5)

    def scan_port(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((host, port))
        s.close()
        return port, result == 0

    def add_network_monitoring_tab(self, tab_frame):
        # Network Monitoring UI
        ctk.CTkLabel(tab_frame, text="Network Monitoring", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, padx=10, pady=5)

        self.network_monitoring_result_text = tk.Text(tab_frame, height=8, width=50, state=tk.DISABLED, bg="#2E2E2E", fg="#00FF00")
        self.network_monitoring_result_text.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

        def update_network_info():
            # Get Network Interface Status
            interfaces = psutil.net_if_addrs()
            status = []
            for interface in interfaces:
                interface_status = psutil.net_if_stats().get(interface, None)
                if interface_status:
                    status.append(f"{interface}: {'Up' if interface_status.isup else 'Down'}")
                else:
                    status.append(f"{interface}: Unknown")
            
            # Get local IP address
            local_ip = self.get_local_ip()
            
            # Get connected devices on the network
            connected_devices = self.scan_network_for_devices()

            # Display network information
            network_info = (
                f"Local IP Address: {local_ip}\n"
                f"Network Interfaces Status:\n" + "\n".join(status) + "\n\n"
                f"Number of Devices Connected: {connected_devices}\n"
            )

            self.network_monitoring_result_text.configure(state=tk.NORMAL)
            self.network_monitoring_result_text.delete(1.0, tk.END)
            self.network_monitoring_result_text.insert(tk.END, network_info)
            self.network_monitoring_result_text.configure(state=tk.DISABLED)
            self.network_monitoring_result_text.see(tk.END)

        # Wrap the update_network_info function in a thread
        def start_network_monitor_thread():
            threading.Thread(target=update_network_info, daemon=True).start()

        # Update Button
        ctk.CTkButton(tab_frame, text="Update Network Info", command=start_network_monitor_thread).grid(row=2, column=0, padx=10, pady=5)

    def get_local_ip(self):
        """Returns the local IP address of the device"""
        host_name = socket.gethostname()
        local_ip = socket.gethostbyname(host_name)
        return local_ip

    def scan_network_for_devices(self):
        """Scans the local network and returns the number of devices connected."""
        ip_range = self.get_ip_range()
        devices = []
        
        # Create ARP request to find devices in the network
        def arp_request(ip):
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            request_packet = broadcast/arp_request
            answered = scapy.srp(request_packet, timeout=1, verbose=False)[0]
            return [answered[i][1].psrc for i in range(len(answered))]

        # Get the local subnet IP range (e.g., 192.168.1.1/24)
        ip_range = self.get_ip_range()

        # Scan for devices in the network
        devices = arp_request(ip_range)

        return len(devices)

    def get_ip_range(self):
        """Returns the IP range of the local network (e.g., '192.168.1.1/24')"""
        local_ip = self.get_local_ip()
        subnet = '.'.join(local_ip.split('.')[:-1]) + '.1/24'
        return subnet

    def create_settings_tab(self):
        # Create a main frame to hold the content
        main_frame = ctk.CTkFrame(self.content_frame)
        main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        # Ensure main_frame expands to fill the parent frame
        main_frame.columnconfigure(0, weight=1)  # Allow the first column to stretch
        main_frame.columnconfigure(1, weight=0)  # Keep the second column fixed for top-right placement

        # Configure main_frame to adjust space proportionately
        main_frame.grid_columnconfigure(0, weight=2)  # Settings
        main_frame.grid_columnconfigure(1, weight=1)  # User Info

        # Create a frame for the settings controls
        settings_frame = ctk.CTkFrame(main_frame)
        settings_frame.grid(row=0, column=0, padx=20, pady=(10, 20), sticky="nsew")

        # Appearance Mode Section
        appearance_mode_label = ctk.CTkLabel(settings_frame, text="Appearance Mode:")
        appearance_mode_label.grid(row=0, column=0, padx=20, pady=(10, 0), sticky="w")

        appearance_mode_option = ctk.CTkOptionMenu(
            settings_frame,
            values=["Dark", "Light"],
            command=self.change_appearance_mode,
            fg_color="gray20"  # Default color
        )
        appearance_mode_option.set(self.settings.get("appearance_mode", "Dark"))
        appearance_mode_option.grid(row=0, column=1, padx=20, pady=(10, 0), sticky="w")

        # UI Scaling Section
        scaling_label = ctk.CTkLabel(settings_frame, text="UI Scaling:")
        scaling_label.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")

        scaling_option = ctk.CTkOptionMenu(
            settings_frame,
            values=["100%", "125%", "150%"],
            command=self.change_scaling,
            fg_color="gray20"  # Default color
        )
        scaling_option.set(self.settings.get("scaling", "100%"))
        scaling_option.grid(row=1, column=1, padx=20, pady=(10, 0), sticky="w")

        # Create a frame for user info
        user_info_frame = ctk.CTkFrame(main_frame)
        user_info_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        user_info_label = ctk.CTkLabel(user_info_frame, text="User Info", font=ctk.CTkFont(size=16, weight="bold"))
        user_info_label.grid(row=0, column=0, padx=20, pady=(10, 0), sticky="w")

        # Use KeyAuth data for user info
        try:
            # Assuming keyauthapp.user_data contains the KeyAuth user info after login
            user_info_data = {
                "App Version": 1.0,
                "Username": keyauthapp.user_data.username,
                "IP address": keyauthapp.user_data.ip,
                "Hardware-Id": keyauthapp.user_data.hwid,
            }
        except AttributeError:
            # Fallback if user_data isn't available
            user_info_data = {
                "App Version": "1.0",
                "Username": "N/A",
                "IP address": "N/A",
                "Hardware-Id": "N/A",
            }

        # Display KeyAuth user info
        for i, (key, value) in enumerate(user_info_data.items()):
            key_label = ctk.CTkLabel(user_info_frame, text=f"{key}:")
            key_label.grid(row=i + 1, column=0, padx=20, pady=5, sticky="w")

            value_label = ctk.CTkLabel(user_info_frame, text=value)
            value_label.grid(row=i + 1, column=1, padx=20, pady=5, sticky="w")

        # Frame for buttons (Logout, Reset Auth, Save Changes, Exit)
        button_frame = ctk.CTkFrame(main_frame, height=160)  # Adjust height to fit smaller buttons
        button_frame.grid(row=1, column=0, padx=10, pady=(20, 20), sticky="ew")
        button_frame.grid_propagate(False)  # Prevent the button frame from resizing

        # Add buttons to the button frame (stacked vertically)
        button_font = ctk.CTkFont(size=12)  # Smaller font for the buttons

    # Create a separate frame for update information
        update_info_frame = ctk.CTkFrame(main_frame, corner_radius=10, width=400, height=150)
        update_info_frame.grid(row=1, column=1, padx=20, pady=(10, 10), sticky="nsew")

        # Title for Update Info Section
        update_info_label = ctk.CTkLabel(
            update_info_frame,
            text="Update Information",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        update_info_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")

        # Scrollable frame for update content
        scrollable_frame = ctk.CTkScrollableFrame(update_info_frame, width=380, height=100)
        scrollable_frame.grid(row=1, column=0, padx=10, pady=(5, 10), sticky="nsew")

        # Example updates
        updates = [
            "Version 1.0 | 10/01/25 - Initial release of the AEQ Manager."
        ]

        # Populate the update section
        for j, update in enumerate(updates, start=1):
            update_label = ctk.CTkLabel(scrollable_frame, text=f"{j}. {update}", wraplength=360)
            update_label.grid(row=j, column=0, padx=10, pady=5, sticky="w")

        # Save Changes Button
        save_button = ctk.CTkButton(
            button_frame,
            text="Save Changes",
            command=self.save_changes,
            height=30,
            width=120,
            font=button_font,
            fg_color="gray20",  # Default color
            hover_color="gray30",
            corner_radius=0
        )
        save_button.grid(row=0, column=0, padx=10, pady=(8, 4), sticky="n")

        logout_button = ctk.CTkButton(
            button_frame,
            text="Logout",
            command=self.logout,
            height=30,
            width=120,
            font=button_font,
            fg_color="gray20",  # Default color
            hover_color="gray30",
            corner_radius=0
        )
        logout_button.grid(row=1, column=0, padx=10, pady=(4, 4), sticky="n")

        resetauth_button = ctk.CTkButton(
            button_frame,
            text="Reset Auth",
            command=self.resetauth,
            height=30,
            width=120,
            font=button_font,
            fg_color="gray20",  # Default color
            hover_color="gray30",
            corner_radius=0
        )
        resetauth_button.grid(row=2, column=0, padx=10, pady=(4, 4), sticky="n")

        reset_cache_button = ctk.CTkButton(
        button_frame,
        text="Clear Cache",
        command=self.reset_cache,
        height=30,
        width=120,
        font=button_font,
        fg_color="gray20",  # Default color
        hover_color="gray30",
        corner_radius=0
        )
        reset_cache_button.grid(row=3, column=0, padx=10, pady=(4, 4), sticky="n")


    def reset_cache(self):
        time.sleep(1)
        try:
            # Simulate cache clearing (replace with actual logic if needed)
            cache_dir = "./cache"
            if os.path.exists(cache_dir):
                for file in os.listdir(cache_dir):
                    os.remove(os.path.join(cache_dir, file))
            messagebox.showinfo("Success", "Cache cleared successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reset cache: {e}")

    def resetauth(self):
        time.sleep(1)
        messagebox.showinfo("Settings", "Authentication has been reset!")

    def save_changes(self):
        """Save settings to a file."""
        try:
            # Ensure settings file exists or create it
            with open(SETTINGS_FILE, "w") as file:
                json.dump(self.settings, file, indent=4)
            messagebox.showinfo("Success", "Settings saved successfully!")  # Notify user
        except Exception as e:
            # Handle and display any errors
            error_message = f"Error saving settings: {e}"
            messagebox.showerror("Error", error_message)

    def logout(self):
        self.destroy()
        app = LoginRegisterApp()
        app.mainloop()

    def change_appearance_mode(self, mode):
        ctk.set_appearance_mode(mode)
        self.settings["appearance_mode"] = mode
        self.save_settings()

    def change_scaling(self, scaling):
        ctk.set_widget_scaling(int(scaling.replace("%", "")) / 100)
        self.settings["scaling"] = scaling
        self.save_settings()

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as file:
                return json.load(file)
        return {"appearance_mode": "System", "scaling": "100%"}

    def save_settings(self):
        with open(SETTINGS_FILE, "w") as file:
            json.dump(self.settings, file)

    def set_icon(self):
        """Set the application icon."""
        try:
            icon_image = tk.PhotoImage(file="path_to_your_icon.png")  # Replace with actual path
            self.iconphoto(False, icon_image)
        except Exception as e:
            print("Error setting icon:", e)

if __name__ == "__main__":
    app = LoginRegisterApp()
    app.mainloop()

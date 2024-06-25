import tkinter as tk
from tkinter import ttk, messagebox
import pyfiglet
import requests
import socket
import json

# Developer Names
DEVELOPERS = "Anshika Awasthi"

def query_whois(ip_address, api_key):
    """
    Queries the Whois API to retrieve information about the given IP address.

    Args:
        ip_address (str): The IP address to query.
        api_key (str): The API key for accessing the Whois API.

    Returns:
        dict: The parsed JSON response from the Whois API, or None if an error occurs.
    """
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&ipAddress={ip_address}&outputFormat=JSON"
    response = requests.get(url)
    if response.status_code == 200:
        try:
            data = response.json()
            return data
        except ValueError as e:
            print("Error:", e)
            print("Invalid JSON response received from WhoisXmlApi.")
            print("Raw response content:", response.content)
            return None
    else:
        print("Error:", response.status_code)
        print("Failed to retrieve Whois information.")
        return None

def get_ip_geolocation(api_key, ip_address):
    """
    Queries the IP Geolocation API to retrieve geolocation information about the given IP address.

    Args:
        api_key (str): The API key for accessing the IP Geolocation API.
        ip_address (str): The IP address to query.

    Returns:
        dict: The parsed JSON response from the IP Geolocation API, or None if an error occurs.
    """
    url = f"https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey={api_key}&ipAddress={ip_address}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def get_builtwith_info(domain, api_key):
    """
    Queries the BuiltWith API to retrieve technology information about the given domain.

    Args:
        domain (str): The domain to query.
        api_key (str): The API key for accessing the BuiltWith API.

    Returns:
        dict: The parsed JSON response from the BuiltWith API, or None if an error occurs.
    """
    url = f"https://api.builtwith.com/free1/api.json?key={api_key}&LOOKUP={domain}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def display_gui():
    """
    Displays the main GUI for the Domain/IP Recon Tool.
    """
    def fetch_info():
        """
        Fetches information about the entered domain/IP and updates the GUI tables.
        """
        domain = domain_entry.get()
        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror:
            messagebox.showerror("Error", "Invalid domain or unable to resolve IP address.")
            return

        whois_data = query_whois(ip_address, api_key)
        geolocation_info = get_ip_geolocation(api_key, ip_address)
        builtwith_info = get_builtwith_info(domain, builtwith_api_key)

        # Update Whois table
        whois_table.delete(*whois_table.get_children())
        if whois_data and 'WhoisRecord' in whois_data:
            whois_record = whois_data['WhoisRecord']
            for key, value in whois_record.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        whois_table.insert("", "end", text="", values=(f"{key} ({sub_key})", sub_value))
                else:
                    whois_table.insert("", "end", text="", values=(key, value))
        else:
            whois_table.insert("", "end", text="", values=("Error", "Failed to retrieve Whois information"))

        # Update BuiltWith table
        builtwith_table.delete(*builtwith_table.get_children())
        if builtwith_info:
            for category, details in builtwith_info.items():
                if isinstance(details, list):
                    for tool in details:
                        builtwith_table.insert("", "end", text="", values=(category, tool))
                else:
                    builtwith_table.insert("", "end", text="", values=(category, details))
        else:
            builtwith_table.insert("", "end", text="", values=("Error", "Failed to retrieve BuiltWith information"))

        # Update IP Geolocation table
        geolocation_table.delete(*geolocation_table.get_children())
        if geolocation_info:
            for key, value in geolocation_info.items():
                geolocation_table.insert("", "end", text="", values=(key, value))
        else:
            geolocation_table.insert("", "end", text="", values=("Error", "Failed to retrieve IP Geolocation information"))

    root = tk.Tk()
    root.title("DomainPro")
    root.configure(bg="#1f1f1f")  # Dark background

    banner = pyfiglet.figlet_format("DomainPro", font="small")
    banner_label = tk.Label(root, text=banner, font=("Courier", 12, "bold"), fg="#00ff00", bg="#1f1f1f")  # Green text, dark background
    banner_label.pack(pady=(10, 5))

    developer_label = tk.Label(root, text="Developed by: " + DEVELOPERS, font=("Helvetica", 10), fg="#00ff00", bg="#1f1f1f")  # Green text, dark background
    developer_label.pack()

    input_frame = tk.Frame(root, bg="#1f1f1f")  # Dark background
    input_frame.pack(padx=20, pady=(10, 5))

    domain_label = tk.Label(input_frame, text="Enter Domain/IP:", bg="#1f1f1f", fg="#00ff00")  # Green text, dark background
    domain_label.grid(row=0, column=0, padx=(0, 10))

    domain_entry = tk.Entry(input_frame, font=("Helvetica", 12), bg="#2b2b2b", fg="#00ff00", insertbackground="#00ff00")  # Dark background, green text, green cursor
    domain_entry.grid(row=0, column=1, padx=(10, 0), ipady=3)

    fetch_button = tk.Button(input_frame, text="Fetch Information", command=fetch_info, bg="#00ff00", fg="#1f1f1f", relief="flat", font=("Helvetica", 12, "bold"))  # Green button, dark background, bold font
    fetch_button.grid(row=0, column=2, padx=(0, 10))

    info_frame = tk.Frame(root, bg="#1f1f1f")
    info_frame.pack(padx=20, pady=10, fill="both", expand=True)

    whois_frame = tk.LabelFrame(info_frame, text="Whois Information", font=("Helvetica", 12, "bold"), bg="#1f1f1f", fg="#00ff00", relief="flat")  # Green text, dark background
    whois_frame.pack(padx=10, pady=10, fill="both", expand=True)

    whois_scrollbar = ttk.Scrollbar(whois_frame, orient="vertical")
    whois_scrollbar.pack(side="right", fill="y")

    whois_table = ttk.Treeview(whois_frame, style="Custom.Treeview", yscrollcommand=whois_scrollbar.set)
    whois_table["columns"] = ("Field", "Value")
    whois_table.column("#0", width=0, stretch=tk.NO)  # Hide first column
    whois_table.column("Field", width=150, anchor=tk.W)
    whois_table.column("Value", width=300, anchor=tk.W)
    whois_table.heading("Field", text="Field", anchor=tk.W)
    whois_table.heading("Value", text="Value", anchor=tk.W)
    whois_table.pack(padx=10, pady=(5, 0), fill="both", expand=True)

    whois_scrollbar.config(command=whois_table.yview)

    builtwith_frame = tk.LabelFrame(info_frame, text="BuiltWith Information", font=("Helvetica", 12, "bold"), bg="#1f1f1f", fg="#00ff00", relief="flat")  # Green text, dark background
    builtwith_frame.pack(padx=10, pady=10, fill="both", expand=True)

    builtwith_scrollbar = ttk.Scrollbar(builtwith_frame, orient="vertical")
    builtwith_scrollbar.pack(side="right", fill="y")

    builtwith_table = ttk.Treeview(builtwith_frame, style="Custom.Treeview", yscrollcommand=builtwith_scrollbar.set)
    builtwith_table["columns"] = ("Category", "Details")
    builtwith_table.column("#0", width=0, stretch=tk.NO)  # Hide first column
    builtwith_table.column("Category", width=150, anchor=tk.W)
    builtwith_table.column("Details", width=300, anchor=tk.W)
    builtwith_table.heading("Category", text="Category", anchor=tk.W)
    builtwith_table.heading("Details", text="Details", anchor=tk.W)
    builtwith_table.pack(padx=10, pady=(5, 0), fill="both", expand=True)

    builtwith_scrollbar.config(command=builtwith_table.yview)

    geolocation_frame = tk.LabelFrame(info_frame, text="IP Geolocation", font=("Helvetica", 12, "bold"), bg="#1f1f1f", fg="#00ff00", relief="flat")  # Green text, dark background
    geolocation_frame.pack(padx=10, pady=10, fill="both", expand=True)

    geolocation_scrollbar = ttk.Scrollbar(geolocation_frame, orient="vertical")
    geolocation_scrollbar.pack(side="right", fill="y")

    geolocation_table = ttk.Treeview(geolocation_frame, style="Custom.Treeview", yscrollcommand=geolocation_scrollbar.set)
    geolocation_table["columns"] = ("Field", "Value")
    geolocation_table.column("#0", width=0, stretch=tk.NO)  # Hide first column
    geolocation_table.column("Field", width=150, anchor=tk.W)
    geolocation_table.column("Value", width=300, anchor=tk.W)
    geolocation_table.heading("Field", text="Field", anchor=tk.W)
    geolocation_table.heading("Value", text="Value", anchor=tk.W)
    geolocation_table.pack(padx=10, pady=(5, 0), fill="both", expand=True)

    geolocation_scrollbar.config(command=geolocation_table.yview)

    # Customize the Treeview style for dark background and green text
    style = ttk.Style()
    style.configure("Custom.Treeview", background="#000000", foreground="#00ff00", fieldbackground="#000000", bordercolor="#00ff00", borderwidth=1, padding=0)  # Dark background, green text, dark field cells, green border lines, no padding

    root.mainloop()

if __name__ == "__main__":
    # Replace these with your own API keys
    api_key = "your_whois_api_key"
    builtwith_api_key = "your_builtwith_api_key"
    display_gui()

import pyshark
import time
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk
from tabulate import tabulate
import socket
import psutil
import logging
import geoip2.database # Import the geoip2 module
import threading

# Configure the logger
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='packet_capture.log',
    filemode='w'
)

# Create a GeoIP reader
geoip_reader = geoip2.database.Reader(r'F:\\3 Fall Sem 2023\\Project Exhibition\\Review 3\\Sample\\GeoLite2-City_20231024\\GeoLite2-City_20231024\\GeoLite2-City.mmdb')

# Global variable to track the current mode (0 for light, 1 for dark)
dark_mode = 1  # Set to dark mode initially

def analyze_packet(packet):
    try:
        timestamp = packet.sniff_time
        protocol = packet.transport_layer if 'IP' in packet else 'N/A'
        src_ip = packet.ip.src if 'IP' in packet else 'N/A'
        dst_ip = packet.ip.dst if 'IP' in packet else 'N/A'
        length = packet.length if hasattr(packet, 'length') else 'N/A'

        # Get geographic location for source IP
        src_location = get_geo_location(src_ip)

        # Get geographic location for destination IP
        dst_location = get_geo_location(dst_ip)

        # Log packet details
        logging.debug(f"Timestamp: {timestamp}")
        logging.debug(f"Protocol: {protocol}")
        logging.debug(f"Source IP: {src_ip} - {src_location}")
        logging.debug(f"Destination IP: {dst_ip} - {dst_location}")
        logging.debug(f"Packet Length: {length}")

        return [timestamp, protocol, f"{src_ip} - {src_location}", f"{dst_ip} - {dst_location}", length, packet]
    except Exception as e:
        # Log any exceptions that occur
        logging.error(f"An error occurred: {e}")
        return []

def get_geo_location(ip_address):
    try:
        response = geoip_reader.city(ip_address)
        city = response.city.name
        country = response.country.name
        return f"{city}, {country}"
    except geoip2.errors.AddressNotFoundError:
        return "Unknown"
    except Exception as e:
        return f"Error: {e}"


def get_wifi_ip_address():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as e:
        return "Unknown"

def get_eth_ip_address():
    try:
        interfaces = psutil.net_if_addrs()
        for interface, addresses in interfaces.items():
            for address in addresses:
                if address.family == socket.AF_INET and not address.address.startswith("127."):
                    return address.address
        return "Unknown"
    except socket.error as e:
        return "Unknown"


def get_network_interfaces():
    return [net_interface for net_interface, _ in psutil.net_if_addrs().items()]

def packet_selected(event):
    # Get the selected packet
    selected_item = packet_tree.selection()
    if selected_item:
        packet_data = packet_tree.item(selected_item, 'values')
        if len(packet_data) > 0:
            show_packet_details(packet_data[-1])  # Pass the packet object to show_packet_details

def show_packet_details(packet):
    if packet:
        # Create a new window for packet inspection
        packet_window = tk.Toplevel()
        packet_window.title("Packet Details")

        packet_text = ScrolledText(packet_window, wrap=tk.WORD, width=80, height=30)
        packet_text.pack()

        details = []

        details.append(f"Timestamp: {packet[0]}")
        details.append(f"Protocol: {packet[1]}")
        details.append(f"Source IP: {packet[2]}")
        details.append(f"Destination IP: {packet[3]}")
        details.append(f"Packet Length: {packet[4]}")

        details.append("\nPacket Details:\n")
        packet_data = packet[5]  # This is where the packet details are stored
        if packet_data:
            for layer in packet_data:
                details.append(f"{layer.layer_name}:")
                for field in layer.field_names:
                    details.append(f"  {field}: {layer.get(field)}")

        packet_text.insert(tk.END, "\n".join(details))
        packet_text.config(state=tk.DISABLED)

def show_captured_data(data):
    wifi_ip_address = get_wifi_ip_address()
    eth_ip_address = get_eth_ip_address()
    wifi_ip_label.config(text=f"Wi-Fi IP Address: {wifi_ip_address}")
    eth_ip_label.config(text=f"Ethernet IP Address: {eth_ip_address}")

    headers = ["Timestamp", "Protocol", "Source IP", "Destination IP", "Packet Length"]
    packet_list = [[row[0], row[1], row[2], row[3], row[4]] for row in data]
    table_str = tabulate(packet_list, headers, tablefmt="pretty")

    captured_data_text.config(state=tk.NORMAL)
    captured_data_text.delete(1.0, tk.END)
    captured_data_text.insert(tk.END, table_str)
    captured_data_text.config(state=tk.DISABLED)

    # Update the packet treeview
    packet_tree.delete(*packet_tree.get_children())
    for packet in data:
        packet_tree.insert('', 'end', values=packet)

def start_capture():
    global capturing, capture_duration
    capturing = True
    capture_duration = int(capture_duration_entry.get())  # Update capture duration

    interface = interface_var.get()  # Get the selected network interface
    capture_filter = capture_filter_var.get()  # Get the selected capture filter
    try:
        capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)
    except Exception as e:
        messagebox.showerror("Error", f"Error: {e}")
        return

    start_time = time.time()
    captured_data = []

    for packet in capture.sniff_continuously():
        if not capturing or (time.time() - start_time) >= capture_duration:
            break
        packet_data = analyze_packet(packet)
        captured_data.append(packet_data)

        # Update the display with the new packet
        show_captured_data(captured_data)
        status_label.config(text="Capturing Packets...")  # Update the status message

    status_label.config(text="Capture Complete")  # Update the status message after capturing

def stop_capture():
    global capturing
    capturing = False
    status_label.config(text="Capture Stopped")  # Update the status message

def refresh_data():
    global capturing
    if capturing:
        messagebox.showinfo("Information", "Stop the capture before refreshing.")
    else:
        captured_data_text.config(state=tk.NORMAL)
        captured_data_text.delete(1.0, tk.END)
        captured_data_text.config(state=tk.DISABLED)
        wifi_ip_label.config(text="Wi-Fi IP Address: Unknown")
        eth_ip_label.config(text="Ethernet IP Address: Unknown")
        status_label.config(text="Data Refreshed")  # Update the status message

capturing = False
capture_duration = 0

root = tk.Tk()
root.title("NETFIELD")
root.geometry("800x600")

# Set the initial background color to dark mode
bg_color = "#36393F"
root.configure(bg=bg_color)

# Wi-Fi IP Address Label
wifi_ip_label = tk.Label(root, text="Wi-Fi IP Address: Unknown", bg=bg_color, fg="white")
wifi_ip_label.pack()

# Ethernet IP Address Label
eth_ip_label = tk.Label(root, text="Ethernet IP Address: Unknown", bg=bg_color, fg="white")
eth_ip_label.pack()

# Network Interface Label and Dropdown Menu
interface_label = tk.Label(root, text="Network Interface:", bg=bg_color, fg="white")
interface_label.pack()
network_interfaces = get_network_interfaces()
interface_var = tk.StringVar(value=network_interfaces[0])  # Default to the first interface
interface_dropdown = ttk.Combobox(root, textvariable=interface_var, values=network_interfaces)
interface_dropdown.pack()

# Capture Filter Label and Dropdown Menu
capture_filter_label = tk.Label(root, text="Capture Filter:", bg=bg_color, fg="white")
capture_filter_label.pack()
capture_filters = ["tcp", "udp", "icmp", "port 80", "port 443", "host 192.168.1.1"]
capture_filter_var = tk.StringVar(value=capture_filters[0])  # Default to the first filter
capture_filter_dropdown = ttk.Combobox(root, textvariable=capture_filter_var, values=capture_filters)
capture_filter_dropdown.pack()

# Capture Duration Entry
duration_label = tk.Label(root, text="Capture Duration (seconds):", bg=bg_color, fg="white")
duration_label.pack()
capture_duration_entry = tk.Entry(root)
capture_duration_entry.pack()

# Capture Button
start_button = tk.Button(root, text="Start Capture", command=start_capture, bg="#43B581", fg="white")
start_button.pack()

# Stop Capture Button
stop_button = tk.Button(root, text="Stop Capture", command=stop_capture, bg="#F04747", fg="white")
stop_button.pack()

# Refresh Data Button
refresh_button = tk.Button(root, text="Refresh Data", command=refresh_data, bg="#7289DA", fg="white")
refresh_button.pack()

# Status Label
status_label = tk.Label(root, text="", bg=bg_color, fg="white")
status_label.pack()

# Captured Data Text
captured_data_text = ScrolledText(root, wrap=tk.NONE, width=80, height=12, font=("Courier", 12), bg="#2C2F33", fg="white")
captured_data_text.pack()

# X Scrollbar
xscrollbar = tk.Scrollbar(root, orient=tk.HORIZONTAL)
xscrollbar.pack(side=tk.BOTTOM, fill=tk.X)
xscrollbar.config(command=captured_data_text.xview)
captured_data_text.config(xscrollcommand=xscrollbar.set)

# Y Scrollbar
yscrollbar = tk.Scrollbar(root, orient=tk.VERTICAL)
yscrollbar.pack(side=tk.RIGHT, fill=tk.Y)
yscrollbar.config(command=captured_data_text.yview)
captured_data_text.config(yscrollcommand=yscrollbar.set)

# Create a Treeview widget for displaying the packets
packet_tree = ttk.Treeview(root, columns=("Timestamp", "Protocol", "Source IP", "Destination IP", "Packet Length"))
packet_tree.heading("#1", text="Timestamp")
packet_tree.heading("#2", text="Protocol")
packet_tree.heading("#3", text="Source IP")
packet_tree.heading("#4", text="Destination IP")
packet_tree.heading("#5", text="Packet Length")
packet_tree.bind("<ButtonRelease-1>", packet_selected)
packet_tree.pack()

root.mainloop()




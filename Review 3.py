import pyshark
import time
from tabulate import tabulate
import tkinter as tk
from tkinter import messagebox

def analyze_packet(packet):
    return [
        packet.sniff_time,
        packet.ip.src,
        packet.ip.dst,
        packet.length,
    ]

def start_capture():
    global capturing
    capturing = True

    interface = interface_entry.get()
    capture_filter = capture_filter_entry.get()
    capture_duration = int(capture_duration_entry.get())

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
        captured_data.append(analyze_packet(packet))

    capture.close()
    show_captured_data(captured_data)

def stop_capture():
    global capturing
    capturing = False

def show_captured_data(data):
    headers = ["Timestamp", "Source IP", "Destination IP", "Packet Length"]
    captured_data_text.set(tabulate(data, headers, tablefmt="grid"))

capturing = False

root = tk.Tk()
root.title("Packet Capture")

# Create and configure GUI elements
interface_label = tk.Label(root, text="Network Interface:")
interface_label.pack()
interface_entry = tk.Entry(root)
interface_entry.pack()

filter_label = tk.Label(root, text="Capture Filter:")
filter_label.pack()
capture_filter_entry = tk.Entry(root)
capture_filter_entry.pack()

duration_label = tk.Label(root, text="Capture Duration (seconds):")
duration_label.pack()
capture_duration_entry = tk.Entry(root)
capture_duration_entry.pack()

start_button = tk.Button(root, text="Start Capture", command=start_capture)
start_button.pack()

stop_button = tk.Button(root, text="Stop Capture", command=stop_capture)
stop_button.pack()

captured_data_text = tk.StringVar()
captured_data_text.set("")
captured_data_label = tk.Label(root, textvariable=captured_data_text)
captured_data_label.pack()

root.mainloop()



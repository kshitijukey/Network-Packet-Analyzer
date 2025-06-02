import pyshark
import threading
import time

def analyze_packet(packet):
    # Your packet analysis code here

 def capture_packets(interface, capture_filter, time_limit):
    cap = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)
    start_time = time.time()

    for packet in cap:
        analyze_packet(packet)

        # Check if the time limit has been reached
        current_time = time.time()
        if current_time - start_time >= time_limit:
            print("Time limit reached. Stopping capture.")
            cap.close()
            break

if __name__ == "__main__":
    interface = "your_network_interface"  # Replace with your network interface (e.g., "eth0")
    capture_filter = "your_capture_filter"  # Replace with your capture filter
    time_limit = 10  # Set the time limit in seconds (e.g., 60 seconds)

    capture_thread = threading.Thread(target=capture_packets, args=(interface, capture_filter, time_limit))
    capture_thread.start()
    capture_thread.join()


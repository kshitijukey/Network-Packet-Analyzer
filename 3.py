import pyshark
import time

def analyze_packet(packet):
    # Implement your analysis logic here
    # For example, you can access packet attributes like packet.ip.src, packet.ip.dst, etc.
 print(f"Timestamp: {packet.sniff_time}")
 print(f"Source IP: {packet.ip.src}")
 print(f"Destination IP: {packet.ip.dst}")
 print(f"Packet Length: {packet.length}")
def main():
    interface = "Wi-fi"  # Change this to your network interface
    capture_filter = "http"  # Adjust the filter as needed (e.g., "udp", "port 80", etc.)

    time.sleep = (10)

    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)


    try:
        for packet in capture.sniff_continuously():
            analyze_packet(packet)
    except KeyboardInterrupt:
        print("Exiting...")


if __name__ == "__main__":
    main()

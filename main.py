import pyshark
import time

def analyze_packet(packet):
    # Implement your analysis logic here
    # For example, you can access packet attributes like packet.ip.src, packet.ip.dst, etc.
    print(f"Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}")

def main():
    interface = "Wi-fi"  # Change this to your network interface
    capture_filter = "tcp"  # Adjust the filter as needed (e.g., "udp", "port 80", etc.)

    time.sleep = (10)

    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)


    try:
        for packet in capture.sniff_continuously():
            analyze_packet(packet)
    except KeyboardInterrupt:
        print("Exiting...")


if __name__ == "__main__":
    main()

import pyshark

# Define a dictionary to keep track of IP addresses and their associated port counts
ip_port_counts = {}

def packet_handler(pkt):
    # Extract Ethernet header information and IP header information
    if "IP" in pkt:
        ip_packet = pkt["IP"]
        src_ip = ip_packet.src
        dst_ip = ip_packet.dst

        if "TCP" in pkt:
            tcp_packet = pkt["TCP"]
            src_port = tcp_packet.srcport
            dst_port = tcp_packet.dstport

            protocol = "TCP"

            if src_ip not in ip_port_counts:
                ip_port_counts[src_ip] = set()

            # Check if the source IP address has initiated a connection to a new destination port
            if dst_port not in ip_port_counts[src_ip]:
                ip_port_counts[src_ip].add(dst_port)
                if len(ip_port_counts[src_ip]) > 10:  # Adjust the threshold as needed
                    print(f"Potential port scan detected from {src_ip}")

def main():
    # Replace 'eth0' with the name of your network interface
    interface = 'Wi-Fi'

    try:
        print(f"Listening on interface {interface}...")
        capture = pyshark.LiveCapture(interface=interface)
        capture.sniff(packet_handler)

    except KeyboardInterrupt:
        print("Capture stopped by user.")

if __name__ == "__main__":
    main()





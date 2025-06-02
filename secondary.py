import pyshark

# Specify the Wi-Fi interface to capture packets from
interface = 'Wi-Fi'  # Change this to your specific Wi-Fi interface name

# Capture packets
capture = pyshark.LiveCapture(interface=interface)

# Start capturing packets indefinitely (use 'timeout' parameter to limit capture duration)
for packet in capture.sniff_continuously():
    try:
        # Access protocol layers (e.g., Ethernet, IP, TCP, UDP)
        ethernet = packet.eth
        ip = packet.ip
        tcp = packet.tcp if 'TCP' in packet else None
        udp = packet.udp if 'UDP' in packet else None

        # Access packet fields
        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.srcport if tcp else None
        dst_port = tcp.dstport if tcp else None

        # Print packet information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        if tcp:
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
        elif udp:
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
        else:
            print("Transport Layer Protocol: Unknown")

        # You can add more specific analysis here based on your requirements

    except Exception as e:
        print(f"An error occurred: {str(e)}")



import psutil
import socket

# Get a list of network interfaces
network_interfaces = psutil.net_if_addrs()

# Print the list of interfaces
for interface, addresses in network_interfaces.items():
    print(f"Interface: {interface}")
    for address in addresses:
        if address.family == socket.AF_INET:
            print(f"  IPv4 Address: {address.address}")
        elif address.family == socket.AF_INET6:
            print(f"  IPv6 Address: {address.address}")
    print()


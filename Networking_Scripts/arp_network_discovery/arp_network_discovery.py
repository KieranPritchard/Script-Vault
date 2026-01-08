from scapy import *

# Function to send arp request to the network
def send_arp(network):
    # Creates an arp request packet
    arp = ARP(pdst=network)
    # Creates an Ethernet broadcast packet
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    # Combines the two packets together
    packet = ether / arp

    # Send the packet and receive responses
    result = srp(packet, timeout=3, verbose=0)[0]

    return result
from scapy.all import *

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

# Function to output results
def output_results(result):
    # stores the client
    clients = []
    # Loops over the received communications in recevied
    for sent, received in result:
        # Adds the received data to client
        clients.append({'ip': received.psrc,'mac': received.hwsrc})
    # Loops over the list of clients
    for client in clients:
        # Outputs the ip and mac address
        print(f"IP: {client['ip']}    MAC: {client['mac']}")

def main():
    network = input("Please enter a network: ")

    arp_result = send_arp(network)

    output_results(arp_result)

if __name__ == "__main__":
    main()
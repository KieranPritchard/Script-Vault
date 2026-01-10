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
    # Logs the starting time
    start_time = time.perf_counter() 

    # Loops the input until it is accepted
    while True:
        try:
            # Allows the user to enter
            network = input("Please enter a network: ")
            # Checks if network was inputed
            if network:
                # Breaks the loop
                break
        except Exception as e:
            # Outputs error message
            print(f"Error Encountered: {e}")

    # Outputs message saying the program is sending arp packets
    print("[+] Sending ARP packet to network")
    # gets the arp result from the send arp function
    arp_result = send_arp(network)

    # Checks if there is a arp result
    if arp_result:
        # Outputs the program found results
        print("[+] Found results")
        # Outputs the program is displaying the results
        print("[+] Displaying results")
        # outputs the results
        output_results(arp_result)
    else:
        print("[-] Results not found")

    # Gets end time and calculates the elasped time
    end_time = time.perf_counter()
    elapsed = end_time - start_time

    # Outputs the time
    print(f"[✓] Finished in {elapsed:.2f} seconds")

# Starts the program
if __name__ == "__main__":
    main()
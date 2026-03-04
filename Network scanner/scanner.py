import scapy.all as scapy
import nmap
import socket

def scan_network():
    target = input("What IP-Range would you like to scan? (192.168.0.0/26): ")
    nm = nmap.PortScanner()
    
    print("\nStart scan on: " + target)
    print("IP Address        MAC Address           Hostname                  OS & Services")
    print("=" * 90)

    # Scapy ARP scan
    # We create a "shout-out" packet. 
    # dst="ff:ff:ff:ff:ff:ff" means we send it to EVERYONE on the local network.
    # scapy.ARP(pdst=target) asks: "Who has the IP addresses in this range?"
    arp_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=target)

    # srp() sends the packet and waits for answers. 
    # 'answered' will contain a list of devices that said "Yes, I am here!"
    answered = scapy.srp(arp_packet, timeout=2, verbose=False, iface="Ethernet")[0]

    if len(answered) == 0:
        print("\nNo Devices found.")
        return

    for sent, received in answered:
        # received.psrc is the IP of the device that answered.
        # received.hwsrc is the MAC address (hardware ID) of that device.
        ip = received.psrc
        mac = received.hwsrc

        
        # Filter
        # This part looks at the very last number of the IP address.
        # If the number is between 50 and 250, we skip it to avoid
        try:
            last_number = int(ip.split('.')[-1])
            if 50 <= last_number <= 250:
                continue
        except:
            pass

        # get Hostname
        # We ask the network: "What is the computer name for this IP address?" 
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        # get OS en Services with Nmap
        # -O: Try to guess the Operating System
        # -F: Fast scan (checks common ports).
        os_info = "Unknown"
        services = []
        try:
            nm.scan(ip, arguments='-O --osscan-guess -F')
            
            # Look through the Nmap results to find the best OS match.
            if 'osmatch' in nm[ip] and len(nm[ip]['osmatch']) > 0:
                os_info = nm[ip]['osmatch'][0]['name']
            
            # Check which 'tcp' ports are open and what they are doing.
            if 'tcp' in nm[ip]:
                for port, data in nm[ip]['tcp'].items():
                    services.append(str(port) + "/" + data['name'])
        except:
            pass

        # Print results
        print(ip.ljust(15) + " " + mac.ljust(19) + " " + hostname.ljust(25) + " " + os_info)
        
        if len(services) > 0:
            for svc in services:
                print("".ljust(61) + " -> " + svc)
        else:
            print("".ljust(61) + " -> no open ports (Firewall)")
        
        print("-" * 90)

if __name__ == "__main__":
    scan_network()
"""end of code"""
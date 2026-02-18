import scapy.all as scapy
import nmap
import socket

def scan_network():
    # 1. Ask for target
    target = input("Enter target IP or range (e.g., 192.168.0.0/26): ")
    nm = nmap.PortScanner()
    
    print(f"\nScanning {target} (Aggressive Mode)...\n")
    print(f"{'IP Address':<15} {'MAC Address':<20} {'Hostname':<25} {'OS & Services'}")
    print("=" * 100)

    # 2. Find Hosts (Scapy)
    arp_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=target)
    answered = scapy.srp(arp_packet, timeout=1, verbose=False)[0]

    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc

        # 3. Filter Students (Range .50 - .250)
        try:
            last_octet = int(ip.split('.')[-1])
            if 50 <= last_octet <= 250:
                continue
        except:
            pass

        # 4. Get Hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        # 5. Get OS & Services (Aggressive)
        os_info = "Unknown"
        services = []
        try:
            # -O checks OS, --osscan-guess guesses if unsure, -F is fast mode
            nm.scan(ip, arguments='-O --osscan-guess -F')
            
            # Check for OS match
            if 'osmatch' in nm[ip] and nm[ip]['osmatch']:
                os_info = nm[ip]['osmatch'][0]['name']
            
            # Check for Open Ports
            if 'tcp' in nm[ip]:
                for port, data in nm[ip]['tcp'].items():
                    services.append(f"{port}/{data['name']}")
        except:
            pass

        # 6. Print Results
        print(f"{ip:<15} {mac:<20} {hostname:<25} {os_info}")
        
        if services:
            for svc in services:
                print(f"{'':<62} -> {svc}")
        else:
            print(f"{'':<62} -> No open ports found (Firewalled)")
        
        print("-" * 100)

if __name__ == "__main__":
    scan_network()
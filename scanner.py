import scapy.all as scapy
import nmap
import socket

def scan_network():
    target = input("Welk IP-bereik wil je scannen? (bijv. 192.168.0.0/26): ")
    nm = nmap.PortScanner()
    
    print("\nStart scan op: " + target)
    print("IP Adres        MAC Adres           Hostname                  OS & Services")
    print("=" * 90)

    # Scapy ARP scan
    arp_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=target)
    answered = scapy.srp(arp_packet, timeout=2, verbose=False, iface="Ethernet")[0]

    if len(answered) == 0:
        print("\nGeen apparaten gevonden. Check of je ethernetkabel goed vastzit en voer VS Code uit als Administrator.")
        return

    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc

        # Negeer studenten laptops (50 t/m 250)
        try:
            laatste_getal = int(ip.split('.')[-1])
            if 50 <= laatste_getal <= 250:
                continue
        except:
            pass

        # Hostname ophalen
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        # OS en Services ophalen met Nmap
        os_info = "Unknown"
        services = []
        try:
            nm.scan(ip, arguments='-O --osscan-guess -F')
            
            if 'osmatch' in nm[ip] and len(nm[ip]['osmatch']) > 0:
                os_info = nm[ip]['osmatch'][0]['name']
            
            if 'tcp' in nm[ip]:
                for port, data in nm[ip]['tcp'].items():
                    services.append(str(port) + "/" + data['name'])
        except:
            pass

        # Printen
        print(ip.ljust(15) + " " + mac.ljust(19) + " " + hostname.ljust(25) + " " + os_info)
        
        if len(services) > 0:
            for svc in services:
                print("".ljust(61) + " -> " + svc)
        else:
            print("".ljust(61) + " -> Geen open poorten (Firewall)")
        
        print("-" * 90)

if __name__ == "__main__":
    scan_network()

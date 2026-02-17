import scapy.all as scapy
import socket
import nmap
import argparse
import sys
import ipaddress

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def is_in_restricted_range(self, ip_str):
        """
        Checks if the IP is in the restricted range 192.168.0.50 - 192.168.0.250.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            start = ipaddress.ip_address("192.168.0.50")
            end = ipaddress.ip_address("192.168.0.250")
            return start <= ip <= end
        except ValueError:
            return False

    def host_discovery(self, target):
        """
        Discovers active hosts using ARP requests (Requirement 1 & 2a, 2b).
        """
        print(f"Scanning target: {target}")
        arp_request = scapy.ARP(pdst=target)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        clients_list = []
        for element in answered_list:
            ip = element[1].psrc
            if not self.is_in_restricted_range(ip):
                client_dict = {"ip": ip, "mac": element[1].hwsrc}
                clients_list.append(client_dict)
            else:
                print(f"Skipping restricted host: {ip}")
        
        return clients_list

    def get_hostname(self, ip):
        """
        Retrieves the hostname using the socket module (Requirement 2e).
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return "Unknown"

    def port_scan(self, ip):
        """
        Scans for open ports using the socket module (Requirement 2c).
        """
        open_ports = []
        # Scanning common ports to maintain efficiency
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports

    def identify_details(self, ip, ports):
        """
        Uses nmap module for service and OS detection (Requirement 2d, 2f).
        """
        details = {"os": "Unknown", "services": {}}
        if not ports:
            return details

        port_str = ",".join(map(str, ports))
        try:
            # -O for OS detection, -sV for service version
            self.nm.scan(ip, port_str, arguments="-O -sV")
            
            if ip in self.nm.all_hosts():
                if "osmatch" in self.nm[ip] and self.nm[ip]["osmatch"]:
                    details["os"] = self.nm[ip]["osmatch"][0]["name"]
                
                for port in ports:
                    if "tcp" in self.nm[ip] and port in self.nm[ip]["tcp"]:
                        service = self.nm[ip]["tcp"][port]["product"] or self.nm[ip]["tcp"][port]["name"]
                        details["services"][port] = service
        except Exception as e:
            details["os"] = f"Error detecting: {e}"
            
        return details

    def display_results(self, hosts):
        """
        Prints the results in a structured format using f-strings (Requirement 3).
        """
        print("\n" + "="*80)
        print(f"{'IP Address':<15} {'MAC Address':<20} {'Hostname':<20} {'OS'}")
        print("-" * 80)
        
        for host in hosts:
            print(f"{host['ip']:<15} {host['mac']:<20} {host['hostname']:<20} {host['os']}")
            if host["services"]:
                print("  Open Ports & Services:")
                for port, service in host["services"].items():
                    print(f"    - Port {port}: {service}")
            print("-" * 80)

def main():
    parser = argparse.ArgumentParser(description="Custom Network Scanner")
    parser.add_argument("-t", "--target", help="Target IP or Subnet (e.g., 192.168.0.1/24)")
    args = parser.parse_args()

    if not args.target:
        target = input("Enter target IP or range (e.g., 192.168.0.1/24): ")
    else:
        target = args.target

    scanner = NetworkScanner()
    discovered_hosts = scanner.host_discovery(target)

    if not discovered_hosts:
        print("No hosts found or all found hosts were in the restricted range.")
        return

    for host in discovered_hosts:
        host["hostname"] = scanner.get_hostname(host["ip"])
        host["ports"] = scanner.port_scan(host["ip"])
        details = scanner.identify_details(host["ip"], host["ports"])
        host["os"] = details["os"]
        host["services"] = details["services"]

    scanner.display_results(discovered_hosts)

if __name__ == "__main__":
    main()
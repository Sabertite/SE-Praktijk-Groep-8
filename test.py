import scapy.all as scapy
import nmap
import sys

def check_setup():
    print(f"Python versie: {sys.version}")
    print(f"Scapy versie: {scapy.conf.version}")
    
    try:
        nm = nmap.PortScanner()
        print("Nmap module is succesvol geladen.")
    except nmap.PortScannerError:
        print("Nmap is gevonden, maar de scanner kon niet starten (is de Nmap software geinstalleerd op je pc?).")
    except Exception as e:
        print(f"Fout bij laden nmap: {e}")

if __name__ == "__main__":
    check_setup()
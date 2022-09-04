from os import link
import time
import socket
import os
import netifaces
import nmap
from rich import print as rprint
from rich import box
from rich.console import Console, group
from rich.prompt import Prompt
from rich.panel import Panel
from rich.padding import Padding
from rich.table import Table
from rich.prompt import Confirm

debug = True

__author__ = "Sophia Kerber"
__license__ = "MIT"

out_interfaces = dict()
out_addrs = dict()
out_network = dict()

# predictable_iface_names = ['eth', 'en', 'wl']

# iface_to_ip_dict = {
#     'eth': False,
#     'en': False,
#     'wl': True,
#     'ww': True
# }

class Network():
    def __init__(self):
        self.gateways = None
        self. hw_addr = None
        self.iface_addrs = None
        self.iface_broadcasts = None
        self.iface_netmask = None

class Device():
    def __init__(self) -> None:
        self.iface = None
        self.ip = None
        self.mac_addr = None


console = Console()

def get_interfaces():
    interfaces = netifaces.interfaces()
    return interfaces

def get_gateways():
    gw_dict = {}
    gws = netifaces.gateways()
    for gw in gws:
        try:
            gw_iface = gws[gw][netifaces.AF_INET]
            gw_ip, iface = gw_iface[0], gw_iface[1]
            gw_list = [gw_ip, iface]
            gw_dict[gw] = gw_list
        except:
            return None
    return gw_dict

def get_addresses(iface):
    addrs = netifaces.ifaddresses(iface)
    
    # AF LINK -> link layer interface (ethernet)
    link_addr = addrs[netifaces.AF_LINK]
    if netifaces.AF_INET in addrs.keys():
        # AF_INET -> normal internet addresses (IPV4)
        out_addrs["ipv4"] = addrs[netifaces.AF_INET]
        # AF_INET6 -> PIV6 internet addresses
        if netifaces.AF_INET6 in addrs.keys():
            out_addrs["ipv6"] = addrs[netifaces.AF_INET6]
        out_interfaces[iface] = out_addrs

    hwaddr = link_addr[0].get('addr')
    iface_addr = out_addrs["ipv4"][0].get('addr')
    iface_broadcast = out_addrs["ipv4"][0].get('broadcast')
    iface_netmask = out_addrs["ipv4"][0].get('netmask')
    return hwaddr, iface_addr, iface_broadcast, iface_netmask

def help():
    pass

def exploit():
    pass

def network():
    pass

def network_info():
    interfaces = get_interfaces()
    gws = get_gateways()
    for iface in interfaces:
        addr = get_addresses(iface)
        out_network[iface] = addr
    
    print("{:<15} {:<25} {:<15} {:<15} {:<15}".format('Interface','MAC Address','IP Address', 'Broadcast', 'Netmask'))
    print("-"*85)
    for k, v in out_network.items():
        mac, ip, broad, netmask = v
        if (broad is None):
            broad = "None"
        print("{:<15} {:<25} {:<15} {:<15} {:<15}".format(k, mac, ip, broad, netmask))
    print("\n")

def OSfingerprinter():
    pass

def nmapScanner(addrs, ports):
    """
    Receives the addresses and ports to scan, and returns a dictionary of open ports
    """
    scanner = nmap.PortScanner()
    scanner.scan(addrs, ports)
    for host in scanner.all_hosts():
        if not scanner[host].hostname():
            print(f"The host's IP address is {host} and its hostname was not found")
        else:
            print(f"The host's IP address is {host} and its hostname is {scanner[host].all_hosts()}")

def ui():
    rprint("\n")
    console.rule("[bold red]SOPA'S PORT SCANNER", style="bold red")
    
    rprint(Padding("[DISCLAIMER]\nUse at your own risk", (2, 4), style='light_sea_green', expand=True))
    if not debug:
        fastscan = Prompt.ask("Would you like to do a fast system scan?", choices=["Y", "n"])
    fastscan = "Y"

    if fastscan == "Y":
        network_info()
        options = ["q", "e", "n"]
        next = Prompt.ask("What next? [Quit (q), Exploitation (e), Network (n)]")
        while next not in options:
            if next == "q":
                quit()
            if next == "e":
                exploit()
            if next == "n":
                network()
            else:
                print("Please choose one of the options")
                next = Prompt.ask("What next? [Quit (q), Exploitation (e), Network (n)]")
        knowledgeable = Confirm.ask("If you choose this option, you are liable for your own actions. \nBeware of the networks you are exploiting: you must have previous consent of the system/network/app admin. \nWould you like to proceed?")
        assert knowledgeable
    pass



if __name__ == "__main__":
    ui()
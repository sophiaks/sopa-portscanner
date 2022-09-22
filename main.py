import socket
from tokenize import String
import netifaces
import nmap
from rich import print as rprint
from rich.console import Console
from rich.prompt import Prompt
from rich.padding import Padding
from rich.prompt import Confirm
import optparse
from socket import *
import inquirer
import sys
from datetime import datetime
from rich.progress import Progress
from scapy.all import srp, Ether, ARP, conf
import ipaddress
from socket import getservbyname, getservbyport

__author__ = "Sophia Kerber"
__license__ = "MIT"

debug = True
console = Console()

out_interfaces = dict()
out_addrs = dict()
out_network = dict()
common_ports = dict()

ip_list = []

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        print('[+] %d/tcp open\n'% tgtPort)
        connSkt.close()
    except:
        print('[-] %d/tcp closed\n'% tgtPort)
    print("-------------------------------")
def portScan(tgtHosts: String, tgtPorts: list):
    for tgtHost in tgtHosts:
        try:
            tgtIP = gethostbyname(tgtHost)
        except:
            print("[-] Cannot resolve '%s': Unknown host"% tgtHost)
            return
        try:
            tgtName = gethostbyaddr(tgtIP)
            #print('\n[+] Scan results for: ' + tgtName.tostring())
            console.rule('\n[+] Scan results for: ' + tgtName.tostring())
        except:
            #print('\n[+] Scan results for: ' + tgtIP)
            console.rule('\n[+] Scan results for: ' + tgtIP)
        setdefaulttimeout(10)
        for tgtPort in tgtPorts:
            try:
                print('\nScanning port ' + str(tgtPort) + ' - ' + getservbyport(int(tgtPort)))
                connScan(tgtHost, int(tgtPort))
            except:
                print("Please specify protocol")

def parserPortScanner():
    # Creating portScanner
    parser = optparse.OptionParser('usage %prog -H' + '<target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='Specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='Specify target port')
    (options, args) = parser.parse_args()
    tgtPort = options.tgtPort
    tgtHost = options.tgtHost
    if (tgtHost == None) | (tgtPort == None):
        print(parser.usage)
        exit(0)

def arp_scan(interface, ips):
    print("\n[*] Scanning")
    with Progress(transient=True) as progress:
        task = progress.add_task("Working", total=100)
        start_time = datetime.now()
        conf.verb = 0
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), \
             timeout = 2, iface=interface, inter=0.1)
        print("MAC - IP\n")
        for snd, rcv in ans:
            print(Ether.src)
            print(ARP.psrc)
            rcv.sprintf("%Ether.src% - %ARP.psrc%")
        stop_time = datetime.now()
        total_time = stop_time - start_time
        print("\n[*] Scan Complete!")
        print(f"[*] Scan Duration: {total_time}")

def shadowAnalysis():

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
    print("Exploit chosen")
    pass

def network():
    print("On network")
    
    pass

def network_info():
    '''
    Prints information for each interface, such as MAC address, IP, boradcast and netmask
    '''
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

def portscanner():
    pass

def ui():
    rprint("\n")
    console.rule("[bold blue]SOPA'S PORT SCANNER", style="bold blue")
    rprint("\n")
    
    fastscan = Prompt.ask("Would you like to do a fast network scan for interfaces?", choices=["y", "n"])
        
    rprint("\n")

    if fastscan == "y":
        network_info()
        answersInitial = {}
        answersInitial["Initial"] = None
        while answersInitial["Initial"] != "Quit":
            questionsInitial = [
            inquirer.List(
                "Initial",
                message="What would you like to use?",
                #choices=["Portscanner", "Fingerprinter", "Network Explorer", "Quit"],
                choices=["Portscanner", "Quit"],
                ),
            ]

            answersInitial = inquirer.prompt(questionsInitial)

            if answersInitial["Initial"] == "Portscanner":
                rprint("[*] Scanning ports for every interface")
                interfaces = get_interfaces()

                # IPS
                print("Please enter the IP or IPs you'd like to scan: (ex.: <192.168.2.1, 127.0.0.1> or 192.168.2.0/28)")
                #ips = '192.168.0.1, 127.0.0.1'
                ips = input()
                if '/' in ips:
                    ip_list = [str(x) for x in ipaddress.ip_network(ips).hosts()]
                else: 
                    ip_list = ips.split(',')
                if len(ip_list) == 0:
                    print("Please enter one or more IPs")

                # PORTS    
                print("Please enter the ports you'd like to scan: (ex.: 22, 200, 2342 or 22-100)")
                ports = input()
                if '-' in ports:
                    portBorders = ports.split('-')
                    portList = range(int(portBorders[0]), int(portBorders[1])+1)
                else:
                    portList = ports.split(',')
                if len(portList) == 0:
                    print("Please enter one or more ports")
                portScan(ip_list, portList)
            if answersInitial["Initial"] == "Quit":
                quit()
            # if answersInitial["Initial"] == "Fingerprinter":
            #     pass
            # if answersInitial["Initial"] == "Network Explorer":
            #     pass
            else:
                print("\nPlease choose one of the options")

        questionsOptions = [
        inquirer.List(
            "Options",
            message="What do you want to do next?",
            #choices=["Quit", "Attack", "Explore Network"],
            choices=["Quit", "Explore Network"],
            ),
        ]

        answers = inquirer.prompt(questionsOptions)

        if answers["Options"] == "Quit":
            quit()
        # if answers["Options"] == "Attack":
        #     exploit()
        if answers["Options"] == "Explore Network":
            network()
        else:
            print("Please choose one of the options")
        
        # knowledgeable = Confirm.ask("If you choose this option, you are liable for your own actions. \nBeware of the networks you are exploiting: you must have previous consent of the system/network/app admin. \nWould you like to proceed?")
        # assert knowledgeable
        
    pass



if __name__ == "__main__":
    ui()
    
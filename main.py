from os import link
import time
import socket
import os
import netifaces
from rich import print as rprint
from rich.console import Console, group
from rich.prompt import Prompt
from rich.panel import Panel

debug = True

__author__ = "Sophia Kerber"
__license__ = "MIT"

predictable_iface_names = ['eth', 'en', 'wl']

iface_to_ip_dict = {
    'eth': False,
    'en': False,
    'wl': True,
    'ww': True
}


console = Console()

def get_interfaces():
    interfaces = netifaces.interfaces()
    return interfaces

def get_gateways():
    gw_dict = {}
    gws = netifaces.gateways()
    for gw in gws:
        try:
            print(gws)
            gw_iface = gws[gw][netifaces.AF_INET]
            gw_ip, iface = gw_iface[0], gw_iface[1]
            gw_list = [gw_ip, iface]
            gw_dict[gw] = gw_list
        except:
            return None
    return gw_dict

def get_addresses(iface):
    addrs = netifaces.ifaddresses(iface)
    link_addr = addrs[netifaces.AF_LINK]
    iface_addrs = addrs[netifaces.AF_INET]
    iface_dict = iface_addrs[0]
    link_dict = link_addr[0]
    hwaddr = link_dict.get('addr')
    iface_addr = iface_dict.get('addr')
    iface_broadcast = iface_dict.get('broadcast')
    iface_netmask = iface_dict.get('netmask')
    return hwaddr, iface_addr, iface_broadcast, iface_netmask



def help():
    pass

@group()
def ui():
    console.rule("[bold red]SOPA'S PORT SCANNER", style="bold red")

    if not debug:
        fastscan = Prompt.ask("Would you like to do a fast system scan?", choices=["Y", "n"])
    fastscan = "Y"

    if fastscan == "Y":
        interfaces = get_interfaces()
        gws = get_gateways()
        for iface in interfaces:
            addr = get_addresses(iface)
            yield Panel(addr, style="on blue")
            

        yield Panel(interfaces, style="on red")
        yield Panel(gws, style="on blue")

    pass


print(Panel(ui()))



if __name__ == "__main__":
    ui()
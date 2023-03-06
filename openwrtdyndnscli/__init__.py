import sys
import argparse
import openwrtdyndnscli
from typing import List
import yaml
import dns.resolver
import netaddr
import netifaces

ipv4_private_net_192_168 = netaddr.IPNetwork('192.168.0.0/16')
ipv4_private_net_172_16 = netaddr.IPNetwork('172.16.0.0/12')
ipv4_private_net_10 = netaddr.IPNetwork('172.16.0.0/12')
ipv6_private_net_fc = netaddr.IPNetwork('fc00::/7') # Unique Local Addresses (ULAs)
ipv6_private_net_fd = netaddr.IPNetwork('fd00::/8') # Management addresses
ipv6_private_net_fe = netaddr.IPNetwork('fe80::/10') # Addresses used for autoconfiguration

def is_public_ipv4(address: str) -> bool:
    addr = netaddr.IPAddress(address)
    return not((addr in ipv4_private_net_10) or (addr in ipv4_private_net_172_16) or (addr in ipv4_private_net_192_168))

def get_ipv4_addresses_linux(interface: str, public_only: bool=True) -> List[str]:
    """
    Find all IPv6 addresses of the given interfaces.
    """

    addrs = netifaces.ifaddresses(interface)
    addrs_list = [addr['addr'] for addr in addrs[netifaces.AF_INET]]
    if public_only:
        return [ addr for addr in addrs_list if is_public_ipv4(addr)]
    return [ addr['addr'] for addr in addrs[netifaces.AF_INET]]

def is_public_ipv6(address: str) -> bool:
    addr = netaddr.IPAddress(address)
    return not((addr in ipv6_private_net_fc) or (addr in ipv6_private_net_fd) or (addr in ipv6_private_net_fe))

def get_ipv6_addresses_linux(interface: str, public_only: bool=True) -> List[str]:
    """
    Find all IPv6 addresses of the given interfaces.
    """

    addrs = netifaces.ifaddresses(interface)
    # Note, that addresses used for autoconfiguration have the format "ipv6_adddr%interface_name"
    addrs_list = [addr['addr'].split('%')[0] for addr in addrs[netifaces.AF_INET6]]
    if public_only:
        return [ addr for addr in addrs_list if is_public_ipv6(addr)]
    return [ addr['addr'] for addr in addrs[netifaces.AF_INET6]]

def get_public_ipv6(hostname: str) -> str:
    result = dns.resolver.query(hostname, 'AAAA')
    # Remove local ones
    for val in result:
        if not val.address.startswith('fd') and not val.address.startswith('fe') and not val.address.startswith('fc'):
            return val.address
    return None

def update_domain(wan_interface, netcup_userid, netcup_apikey, netcup_apipass, domain):
    print (domain)

def update(config)->int:
    wan_interface = config['wan_interface']
    netcup_userid = config['netcup_userid']
    netcup_apikey = config['netcup_apikey']
    netcup_apipass = config['netcup_apipass']
    domains = config['domains']
    for domain in domains:
        update_domain(wan_interface, netcup_userid, netcup_apikey, netcup_apipass, domain)
    #print(get_ipv4_addresses_linux(config['wan_interface']))
    #print(get_ipv6_addresses_linux(config['wan_interface']))
    #print (get_public_ipv6('homeassistant.lan'))
    #print (get_public_ipv6('turris.lan'))
    return 0

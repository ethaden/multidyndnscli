import sys
import argparse
import openwrtdyndnscli
from typing import List, Tuple
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

def update_domain(netcup_config, router_config, domain_config):
    domain_name = domain_config['name']
    
    print (domain_config)

class RouterAddresses:

    def _get_public_ipv4(self, ipv4_config) -> str:
        if ipv4_config['method'] == 'web':
            url = ipv4_config['url']
            #print ('Using URL to get external IPv4: {url}')
        elif ipv4_config['method'] == 'wan':
            wan_interface = ipv4_config['wan_interface']
            #print ('Using wan interface as source for IPv4: {wan_interface}')
            self.wan_interface_ipv4 = ipv4_config['wan_interface']
            ipv4_list = get_ipv4_addresses_linux(self.wan_interface_ipv4)
            # Return first address if any
            return None if len(ipv4_list)==0 else ipv4_list[0]
        return None

    def _get_public_ipv6(self, ipv6_config) -> str:
        if ipv6_config['method'] == 'web':
            url = ipv6_config['url']
            print ('Using URL to get external IPv4: {url}')
        elif ipv6_config['method'] == 'wan':
            self.wan_interface_ipv6 = ipv6_config['wan_interface']
            ipv6_list = get_ipv6_addresses_linux(self.wan_interface_ipv6)
            # Return first address if any
            return None if len(ipv6_list)==0 else ipv6_list[0]
        return None

    def __init__(self, config):
        router_config = config['router']
        router_ipv4_config = router_config['ipv4']
        router_ipv6_config = router_config['ipv4']
        self.use_ipv4 = router_ipv4_config.get('enabled', False)
        self.use_ipv6 = router_ipv6_config.get('enabled', False)
        self.ipv4 = None
        self.ipv6 = None
        self.wan_interface_ipv4 = None
        self.wan_interface_ipv6 = None
        if self.use_ipv4:
            self.ipv4 = self._get_public_ipv4(router_config['ipv4'])
            print (f'Router has external IPv4: {self.ipv4}')
        if self.use_ipv6:
            self.ipv6 = self._get_public_ipv6(router_config['ipv6'])
            print (f'Router has external IPv6: {self.ipv6}')
        

class NetcupConfig:
    def __init__(self, config):
        netcup_config = config['netcup']
        self.netcup_userid = netcup_config['userid']
        self.netcup_apikey = netcup_config['apikey']
        self.netcup_apipass = netcup_config['apipass']

def update(config)->int:
    netcup_config = NetcupConfig(config)
    router_config = RouterAddresses(config)
    domain_config_list = config['domains']
    for domain_config in domain_config_list:
        update_domain(netcup_config, router_config, domain_config)
    #print(get_ipv4_addresses_linux(config['wan_interface']))
    #print(get_ipv6_addresses_linux(config['wan_interface']))
    #print (get_public_ipv6('homeassistant.lan'))
    #print (get_public_ipv6('turris.lan'))
    return 0

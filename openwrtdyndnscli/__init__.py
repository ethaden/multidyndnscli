import sys
import argparse
import openwrtdyndnscli
from typing import List, Optional, Tuple
import yaml
import dns.resolver
import netaddr
import netifaces
import requests

ipv4_private_net_192_168 = netaddr.IPNetwork('192.168.0.0/16')
ipv4_private_net_172_16 = netaddr.IPNetwork('172.16.0.0/12')
ipv4_private_net_10 = netaddr.IPNetwork('172.16.0.0/12')
ipv6_private_net_fc = netaddr.IPNetwork('fc00::/7') # Unique Local Addresses (ULAs)
ipv6_private_net_fd = netaddr.IPNetwork('fd00::/8') # Management addresses
ipv6_private_net_fe = netaddr.IPNetwork('fe80::/10') # Addresses used for autoconfiguration

def get_valid_ip(address: str) -> netaddr.IPAddress:
    addr = netaddr.IPAddress(address)
    return addr


def is_public_ipv4(address: netaddr.IPAddress) -> bool:
    return not((address in ipv4_private_net_10) or (address in ipv4_private_net_172_16) or (address in ipv4_private_net_192_168))

def get_ipv4_addresses_linux(interface: str, public_only: bool=True) -> List[netaddr.IPAddress]:
    """
    Find all IPv6 addresses of the given interfaces.
    """

    addrs = netifaces.ifaddresses(interface)
    address_string_list = [addr['addr'] for addr in addrs[netifaces.AF_INET]]
    address_list = [ get_valid_ip(address) for address in address_string_list]
    if public_only:
        return [ addr for addr in address_list if is_public_ipv4(addr)]
    return address_list

def is_public_ipv6(address: netaddr.IPAddress) -> bool:
    return not((address in ipv6_private_net_fc) or (address in ipv6_private_net_fd) or (address in ipv6_private_net_fe))

def get_ipv6_addresses_linux(interface: str, public_only: bool=True) -> List[str]:
    """
    Find all IPv6 addresses of the given interfaces.
    """

    addrs = netifaces.ifaddresses(interface)
    # Note, that addresses used for autoconfiguration have the format "ipv6_adddr%interface_name"
    address_string_list = [addr['addr'].split('%')[0] for addr in addrs[netifaces.AF_INET6]]
    addresses_list = [ get_valid_ip(address) for address in address_string_list]
    if public_only:
        return [ addr for addr in addresses_list if is_public_ipv6(addr)]
    return addresses_list

def get_public_ipv6(hostname: str) -> netaddr.IPAddress:
    result_list = dns.resolver.query(hostname, 'AAAA')
    # Remove local ones
    for val in result_list:
        if not val.address.startswith('fd') and not val.address.startswith('fe') and not val.address.startswith('fc'):
            return get_valid_ip(val.address)
    return None

def update_domain(netcup_config, router_config, domain_config):
    domain_name = domain_config['name']
    
    print (domain_config)

class RouterConfig:

    def _get_public_ipv4(self, ipv4_config) -> netaddr.IPAddress:
        if ipv4_config['method'] == 'web':
            url = ipv4_config['url']
            #print ('Using URL to get external IPv4: {url}')
            response = requests.get(url)
            if response:
                ipv4_candidate = response.text
                return get_valid_ip(ipv4_candidate)
            else:
                raise Exception(f'Unable to determine external IPv4 of router through website {url}')
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

    def __init__(self, config_dict):
        router_public_address_config = config_dict['router_public_address']
        self.use_ipv4 = config_dict.get('use_ipv4', False)
        self.use_ipv6 = config_dict.get('use_ipv6', False)
        self.ipv4 = None
        self.ipv6 = None
        self.wan_interface_ipv4 = None
        self.wan_interface_ipv6 = None
        if self.use_ipv4:
            self.ipv4 = self._get_public_ipv4(router_public_address_config['ipv4'])
            print (f'Router has external IPv4: {self.ipv4}')
        if self.use_ipv6:
            self.ipv6 = self._get_public_ipv6(router_public_address_config['ipv6'])
            print (f'Router has external IPv6: {self.ipv6}')
        

class NetcupConfig:
    def __init__(self, netcup_config_dict):
        self.netcup_userid = netcup_config_dict['netcup_userid']
        self.netcup_apikey = netcup_config_dict['netcup_apikey']
        self.netcup_apipass = netcup_config_dict['netcup_apipass']

class HostConfig:
    def __init__(self, domain_config, host_config_dict):
        self.domain_config = domain_config
        self.name = host_config_dict['name']
        self.fqdn = host_config_dict['fqdn']
        public_ip_methods = host_config_dict.get('public_ip_methods', None)
        if public_ip_methods is not None:
            self.public_ip_method_ipv4 = public_ip_methods.get('ipv4')
            self.public_ip_method_ipv6 = public_ip_methods.get('ipv4')
        print (f'Reading settings for hostname {self.name}')

    def is_up_to_date(self) -> bool:
        pass

    def get_record_ipv4(self):
        pass

class DomainConfig:
    host_configs = []

    def _get_host_settings(self, config_host_dict):
        pass
        
    def __init__(self, router_config, netcup_config, domain_config_dict):
        self.router_config = router_config
        self.netcup_config = netcup_config
        self.domain_name = domain_config_dict['name']
        for host_config_dict in domain_config_dict['hosts']:
            self.host_configs.append(HostConfig(self, host_config_dict))
    
    def get_router_config(self) -> RouterConfig:
        return self.router_config

    def update(self):
        print (f'Updating addresses for domain "{self.domain_name}"')

def update(config_dict)->int:
    netcup_config = NetcupConfig(config_dict)
    router_config = RouterConfig(config_dict)
    domain_config_list = config_dict['domains']
    for domain_config_dict in domain_config_list:
        domain_config = DomainConfig(netcup_config, router_config, domain_config_dict)
        domain_config.update()

    #print(get_ipv4_addresses_linux(config['wan_interface']))
    #print(get_ipv6_addresses_linux(config['wan_interface']))
    #print (get_public_ipv6('homeassistant.lan'))
    #print (get_public_ipv6('turris.lan'))
    return 0

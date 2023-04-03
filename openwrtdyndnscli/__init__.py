import sys
import argparse
import openwrtdyndnscli
from typing import List, Optional, Tuple
import yaml
import dns.resolver
import netaddr
import requests
import logging

from .util import *

class NetworkAddressException(Exception):
    pass

class RouterNotReachableException(Exception):
    pass

class DomainConfig:

    def __init__(self, domain_config):
        self._domain_name = domain_config['name']
    
    def update(self):
        print (self._domain_name)

class RouterConfig:

    def _get_public_ipv4(self, ipv4_config) -> netaddr.IPAddress:
        if ipv4_config['method'] == 'web':
            url = ipv4_config['url']
            response = requests.get(url)
            if response:
                ipv4_candidate = response.text
                return get_valid_ip(ipv4_candidate)
            else:
                raise Exception(f'Unable to determine external IPv4 of router through website {url}')
        elif ipv4_config['method'] == 'wan':
            wan_interface = ipv4_config['wan_interface']
            self._wan_interface_ipv4 = ipv4_config['wan_interface']
            ipv4_list = get_ipv4_addresses_linux(self._wan_interface_ipv4)
            # Return first address if any
            return None if len(ipv4_list)==0 else ipv4_list[0]
        elif ipv4_config['method'] == 'fritzbox':
            from fritzconnection import FritzConnection
            from fritzconnection.lib.fritzstatus import FritzStatus
            from fritzconnection.core.exceptions import FritzConnectionException
            fritzbox_config = ipv4_config['fritzbox']
            fritz_ip = fritzbox_config.get('address')
            fritz_tls = fritzbox_config.get('tls', False)
            try:
                fc = FritzConnection(address=fritz_ip,  use_tls=fritz_tls)
                status = FritzStatus(fc)
            except FritzConnectionException as exc:
                raise RouterNotReachableException('Unable to connect to Fritz!Box') from exc
            return status.external_ip
        return None

    def _get_public_ipv6(self, ipv6_config) -> str:
        if ipv6_config['method'] == 'web':
            url = ipv6_config['url']
            response = requests.get(url)
            if response:
                ipv6_candidate = response.text
                return get_valid_ip(ipv6_candidate)
            else:
                raise Exception(f'Unable to determine external IPv6 of router through website {url}')
        elif ipv6_config['method'] == 'wan':
            self._wan_interface_ipv6 = ipv6_config['wan_interface']
            ipv6_list = get_ipv6_addresses_linux(self._wan_interface_ipv6)
            # Return first address if any
            return None if len(ipv6_list)==0 else ipv6_list[0]
        return None

    def __init__(self, config):
        router_config = config['router']
        router_ipv4_config = router_config['ipv4']
        router_ipv6_config = router_config['ipv6']
        self._use_ipv4 = router_ipv4_config.get('enabled', False)
        self._use_ipv6 = router_ipv6_config.get('enabled', False)
        self._ipv4 = None
        self._ipv6 = None
        self._wan_interface_ipv4 = None
        self._wan_interface_ipv6 = None
        if self._use_ipv4:
            try:
                self._ipv4 = self._get_public_ipv4(router_config['ipv4'])
            except RouterNotReachableException as exc:
                raise exc
            logging.info (f'Router has external IPv4: {self._ipv4}')
        if self._use_ipv6:
            try:
                self._ipv6 = self._get_public_ipv6(router_config['ipv6'])
            except RouterNotReachableException as exc:
                raise exc
            logging.info (f'Router has external IPv6: {self._ipv6}')

    @property
    def ipv4(self):
        return self._ipv4

    @property
    def use_ipv4(self):
        return self._use_ipv4

    @property
    def ipv6(self):
        return self._ipv6

    @property
    def use_ipv6(self):
        return self._use_ipv6


class NetcupConfig:
    def __init__(self, config):
        netcup_config = config['netcup']
        self._userid = netcup_config['userid']
        self._apikey = netcup_config['apikey']
        self._apipass = netcup_config['apipass']

def update(config)->int:
    try:
        netcup_config = NetcupConfig(config)
        router_config = RouterConfig(config)
        domain_config_list = config['domains']
        for domain_config_dict in domain_config_list:
            domain_config = DomainConfig(domain_config_dict)
            domain_config.update()
    except RouterNotReachableException as e:
        logging.error(e)
        return 1
    return 0

import datetime
from pathlib import Path
import pickle
import sys
import argparse
import openwrtdyndnscli
from typing import Final, List, Optional, Tuple, Dict
import yaml
from schema import Schema, SchemaError
import dns.resolver
from netaddr import IPAddress
import requests
import logging
from nc_dnsapi import Client, DNSRecord
from abc import ABC, abstractmethod

from .util import *
from .schemata import *

class NetworkAddressException(Exception):
    pass

class RouterNotReachableException(Exception):
    pass

class Domain:
    _updater: 'Updater' = None
    _delay: Optional(int) = None
    _target_records_ipv4: Dict[str, netaddr.IPAddress] = {}
    _target_records_ipv6: Dict[str, netaddr.IPAddress] = {}
    _router: 'Router' = None
    _domain_name: str = None
    _dns_provider: 'DNSProvider' = None
    _last_update: datetime.datetime = None
    _key_domains: Final[str] = "domains"
    _key_last_update: Final[str] = "last_updated"

    def __init__(self, updater: 'Updater', router, dns_providers: Dict[str, 'DNSProvider'], domain_config):
        self._updater = updater
        self._router = router
        self._domain_name = domain_config['name']
        self._dns_provider = dns_providers[domain_config['dns-provider']]
        self._delay = domain_config.get('delay', None)
        hosts_config = domain_config['hosts']
        for host_config in hosts_config:
            name = host_config['name']
            fqdn = host_config['fqdn']
            public_ip_methods = host_config['public_ip_methods']
            if 'ipv4' in public_ip_methods:
                self._add_target_record_ipv4(name, fqdn, public_ip_methods['ipv4'])
            if 'ipv6' in public_ip_methods:
                self._add_target_record_ipv6(name, fqdn, public_ip_methods['ipv6'])
    
    def _read_from_cache(self):
        cache = self._updater.cache
        if cache is not None:
            if self._key_domains in cache:
                domains_cache = cache[self._key_domains]
                if self._domain_name in domains_cache:
                    domain_cache = domains_cache[self._domain_name]
                    if self._key_last_update in domain_cache:
                        self._last_update = domain_cache[self._key_last_update]

    def _add_target_record_ipv4(self, name: str, fqdn: str, method: str):
        address = None
        if method == 'router':
            address = self._router.ipv4
        elif method == 'local_dns':
            try:
                result = dns.resolver.resolve(name, rdtype=dns.rdatatype.A)
                if len(result.rrset) > 0:
                    address = result.rrset[0].address
            except Exception as e:
                raise Exception(f'Local fqdn not found: {name}')

        if address is not None:
            self._target_records_ipv4[fqdn] = IPAddress(address)

    def _add_target_record_ipv6(self, name: str, fqdn: str, method: str):
        address = None
        if method == 'router':
            address = self._router.ipv6
        elif method == 'local_dns':
            try:
                result = dns.resolver.resolve(name, rdtype=dns.rdatatype.AAAA)
                for address_result in result.rrset:
                    address_candidate = IPAddress(address_result.address)
                    if is_public_ipv6(address_candidate):
                        address = address_candidate
                        break
            except Exception as e:
                raise Exception(f'Local fqdn not found: {name}')
        if address is not None:
            self._target_records_ipv6[fqdn] = address

    def update(self):
        self._last_update = datetime.datetime.now()
        print (f'Updating domain: {self._domain_name}')
        record_dict = {}
        records = self._dns_provider.fetch_domain(self)
        for record in records:
            hostname_dict = record_dict.get(record.hostname, {})
            hostname_dict[record.type] = record
            record_dict[record.hostname] = hostname_dict
        domain_cache = self._updater.get_cache_domain(self._domain_name)
        domain_cache[self._key_last_update] = self._last_update
        self._updater.update_cache_domain(self._domain_name, domain_cache)

    @property
    def domain_name(self):
        return self._domain_name


class Router:

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


class DNSProvider(ABC):
    pass

    @abstractmethod
    def fetch_domain(self, domain: Domain) -> List[DNSRecord]:
        pass

class Netcup(DNSProvider):
    def __init__(self, config):
        self._userid = config['userid']
        self._apikey = config['apikey']
        self._apipass = config['apipass']

    def fetch_domain(self, domain: Domain) -> List[DNSRecord]:
        with Client(self._userid, self._apikey, self._apipass) as api:
            # fetch records
            return api.dns_records(domain.domain_name)
        return []
    
    def update_domain(self, domain: Domain, records: List[DNSRecord]):
        pass


class Updater():

    _config = None
    _cache_file: Path = None
    _cache = {}

    def __init__(self, config):
        self._config = config
        if 'common' in self._config:
            if 'cache_dir' in self._config['common']:
                cache_dir_str = self._config['common']['cache_dir']
                cache_dir = Path(cache_dir_str)
                if cache_dir.exists() or cache_dir.is_dir():
                    self._cache_file = cache_dir / 'cache.json'
                    self._read_cache()

    def _read_cache(self):
        if self._cache_file.exists():
            with open(self._cache_file, 'r') as f:
                self._cache = yaml.safe_load(f)
                if self._cache is None:
                    self._cache = {}

    def _write_cache(self):
        if self._cache_file is not None:
            with open(self._cache_file, 'w') as f:
                yaml.dump(self._cache, f)


    def get_cache_domain(self, domain: str) -> Dict:
        return self._cache.get(domain, {})
    
    def update_cache_domain(self, domain: str, domain_cache):
        self._cache[domain] = domain_cache
        self._write_cache()

    def update(self)->int:
        try:
            dns_provider_list = self._config['dns-providers']
            dns_providers: Dict[str, DNSProvider] = {}
            for provider in dns_provider_list:
                name = provider['name']
                provider_type = provider['type'].lower()
                if provider_type == 'netcup':
                    dns_providers[name] = Netcup(provider)
            router = Router(self._config)
            domain_config_list = self._config['domains']
            for domain_config_dict in domain_config_list:
                domain = Domain(self, router, dns_providers, domain_config_dict)
                domain.update()
        except RouterNotReachableException as e:
            logging.error(e)
            return 1
        return 0

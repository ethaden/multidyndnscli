"""
Yet another python module for router-based multi-domain, multi-host dynamic dns (dyndns), 
with support for IPv4 and IPv6.
This project currently only support Netcup, but might be extended in the future.
"""
import datetime
from pathlib import Path
from typing import Any, Final, List, Dict, Optional, Set
import netaddr  # type: ignore
import yaml
import dns.resolver
from netaddr import IPAddress, AddrFormatError
import requests
import logging
from nc_dnsapi import Client, DNSRecord  # type: ignore
from abc import ABC, abstractmethod
from . import util
from .schemata import get_config_file_schema
import fritzconnection  # type: ignore
import fritzconnection.lib.fritzstatus  # type: ignore
import fritzconnection.core.exceptions  # type: ignore

CACHE_FILE_NAME = 'multidyndns.cache'
"""The name used for the updater cache file if a (valid) cache dir has been configured"""
KEY_DOMAINS: Final[str] = 'domains'
"""The key used to store domain statuses in the updater cache"""
KEY_LAST_UPDATE: Final[str] = 'last_updated'
"""The key used to store the datetime of the last update into the updater cache"""

class RouterNotReachableException(Exception):
    """This exception indicates that the Fritz!Box couldn't be reached"""


class DNSResolutionException(Exception):
    """This exception indicates that an IP address couldn't not be resolved"""


class Host:
    """Represents a host in the local network used as target for an external address"""

    _name: str
    """The local hostname of the host"""
    _router: 'Router'
    """A router object, representing the home router"""
    _current_fqdn_dns_ipv4: Optional[IPAddress]
    """The IPv4 the FQDN is currently pointing to (if any)"""
    _current_fqdn_dns_ipv6_set: Set[IPAddress]
    """The set of IPv6 the FQDN is currently pointing to (if any)"""
    _host_ipv4: Optional[IPAddress]
    """The IPv4 the host is currently using (if any)"""
    _host_ipv6_set: Set[IPAddress]
    """# The set of IPv6 the host is currently using (if any)"""

    def __init__(
        self,
        router: 'Router',
        name: str,
        fqdn: str,
        public_ipv4_method: Optional[str],
        public_ipv6_method: Optional[str],
    ):
        """Constructor of class Host

        :param router: An instance of the Router class, representing the home router
        :type router: Router
        :param name: The local hostname of the host
        :type name: str
        :param fqdn: The desired public fully qualidifed domain name (FQDN)
        :type fqdn: str
        :param public_ipv4_method: The method how to resolve the public IPv4 to use.
        :type public_ipv4_method: str, optional
        :param public_ipv6_method: The method how to resolve the public IPv6 to use.
        :type public_ipv6_method: str, optional
        """
        self._router = router
        self._name = name
        self._fqdn = fqdn
        self._current_fqdn_dns_ipv4 = None
        self._current_fqdn_dns_ipv6_set = set()
        self._host_ipv4 = None
        self._host_ipv6_set = set()
        if public_ipv4_method is not None:
            self._resolve_current_fqdn_ipv4()
            self._resolve_host_ipv4(public_ipv4_method)
        if public_ipv6_method is not None:
            self._resolve_host_ipv6_set(public_ipv6_method)
            if len(self._host_ipv6_set) > 0:
                self._resolve_current_fqdn_ipv6_set()

    @staticmethod
    def from_config(router: 'Router', host_config) -> 'Host':
        """Dictionary-based factory for instances of type Host

        :param router: An instance of the Router class, representing the home router
        :type router: Router
        :param host_config: A dictionary holding the configuration of this host
        :type host_config: _type_
        :return: A Host instance if the config dictionary has been parsed successfully
        :rtype: Host
        """
        public_ip_methods = host_config['public_ip_methods']
        return Host(
            router,
            host_config['name'],
            host_config['fqdn'],
            public_ip_methods.get('ipv4', None),
            public_ip_methods.get('ipv6', None),
        )

    def _resolve_current_fqdn_ipv4(self):
        """Method for resolving the current IPv4 the FQDN is pointing to (if any)
        """
        try:
            result = dns.resolver.resolve(self._fqdn, rdtype=dns.rdatatype.A)
            if len(result.rrset) > 0:
                self._current_fqdn_dns_ipv4 = IPAddress(result.rrset[0].address)
        except (ValueError, AddrFormatError):
            self._current_fqdn_dns_ipv4 = None

    def _resolve_current_fqdn_ipv6_set(self):
        """Method for resolving the current IPv6 the FQDN is pointing to (if any)
        """
        addresses = set()
        try:
            result = dns.resolver.resolve(self._fqdn, rdtype=dns.rdatatype.AAAA)
            for rrset_address in result.rrset:
                address = IPAddress(rrset_address.address)
                if util.is_public_ipv6(address):
                    addresses.add(address)
            self._current_fqdn_dns_ipv6_set = addresses
        except (ValueError, AddrFormatError):
            self._current_fqdn_dns_ipv6_set = set()

    def _resolve_host_ipv4(self, method: str):
        """Method for resolving the public IPv4 used to reach the host from the intranet
        """
        address = None
        if method == 'router':
            address = self._router.ipv4
        elif method == 'local_dns':
            try:
                result = dns.resolver.resolve(self._name, rdtype=dns.rdatatype.A)
                if result.rrset is not None and len(result.rrset) > 0:
                    address = result.rrset[0].address
            except (ValueError, AddrFormatError) as exc:
                raise DNSResolutionException(
                    f'Unable to find IPv4 for local hostname {self._name}') from exc

        if address is not None:
            self._host_ipv4 = IPAddress(address)

    def _resolve_host_ipv6_set(self, method: str):
        """Method for resolving the set of public IPv6 used to reach the host from the intranet
        """
        addresses = set()
        if method == 'router':
            if self._router.ipv6 is not None:
                addresses.add(IPAddress(self._router.ipv6))
        elif method == 'local_dns':
            try:
                result = dns.resolver.resolve(self._name, rdtype=dns.rdatatype.AAAA)
                if result.rrset is None:
                    return
                for result_addr in result.rrset:
                    address = IPAddress(result_addr.address)
                    if util.is_public_ipv6(address):
                        addresses.add(address)
            except (ValueError, AddrFormatError) as exc:
                raise DNSResolutionException(
                    f'Unable to find IPv6s for local hostname {self._name}') from exc
        if len(addresses) > 0:
            self._host_ipv6_set = addresses

    def needs_update(self) -> bool:
        """Indicates whether or not an update of the FQDN is required for this host
        """
        if self._host_ipv4 is not None:
            if self._current_fqdn_dns_ipv4 is None:
                return True
            if self._current_fqdn_dns_ipv4 != self._host_ipv4:
                return True
        if len(self._host_ipv6_set) > 0:
            # Find disjoint set. An update is only required if none of the current
            # addresses is in the set of target addresses
            common_addresses = self._current_fqdn_dns_ipv6_set & self._host_ipv6_set
            if len(common_addresses) == 0:
                return True
        return False

    @property
    def host_ipv4(self):
        """Property holding the resolved public IPv4 for connections from the internet (if any)
        """
        return self._host_ipv4

    @property
    def host_ipv6(self):
        """Property holding the resolved public IPv6 for connections from the internet (if any)
        """
        if self._host_ipv6_set is None or len(self._host_ipv6_set) == 0:
            return None
        return list(self._host_ipv6_set)[0]

    @property
    def name(self):
        """Property holding the name of this host
        """
        return self._name

    @property
    def fqdn(self):
        """Property holding the public fully qualified domain name (FQDN) of this host
        """
        return self._fqdn


class Domain:
    """This class represents an internet domain containing hosts used for dyndns
    """
    _updater: 'Updater'
    """An instance of the Updater class"""
    _delay: int
    """A delay to wait between DNS updates, in seconds"""
    _target_records_ipv4: Dict[str, netaddr.IPAddress]
    """A dictionary of hostnames mapping to their respective desired public IPv4 address"""
    _target_records_ipv6: Dict[str, netaddr.IPAddress]
    """A dictionary of hostnames mapping to their respective desired public IPv6 address"""
    _router: 'Router'
    """An instance of the Router class, representing the home router"""
    _domain_name: str
    """The domain name of this domain (FQDN)"""
    _dns_provider: 'DNSProvider'
    """An instance of a DNSProvider, used to update the domain records"""
    _last_update: Optional[datetime.datetime]
    """The datetime of the last updated (optionally, if available)"""
    _host_list: List[Host]
    """The list of Host instances to do dyndns for in this domain"""
    _domain_record_dict: Dict[str, Dict[str, Dict[str, DNSRecord]]]
    """A dictionary for hostnames to record type to IP addresses"""

    def __init__(
        self,
        updater: 'Updater',
        router: 'Router',
        domain_name: str,
        dns_provider: 'DNSProvider',
        delay: int = 0,
    ):
        """Constructor of the Domain class

        :param updater: An instance of the Updater class
        :type updater: Updater
        :param router: An instance of the Router class, representing the home router
        :type router: Router
        :param domain_name: The domain name of this domain (FQDN)
        :type domain_name: str
        :param dns_provider: An instance of a DNSProvider, used to update the domain records
        :type dns_provider: DNSProvider
        :param delay: A delay to wait between DNS updates, in seconds, defaults to 0
        :type delay: int, optional
        """
        self._updater = updater
        self._router = router
        self._domain_name = domain_name
        self._dns_provider = dns_provider
        self._delay = delay
        self._host_list = []
        self._target_records_ipv4 = {}
        self._target_records_ipv6 = {}
        self._last_update = None
        self._domain_record_dict = {}
        # Initialize values from cache if any
        self._read_from_cache()

    @staticmethod
    def from_config(
        updater: 'Updater',
        router: 'Router',
        dns_providers: Dict[str, 'DNSProvider'],
        domain_config,
    ) -> 'Domain':
        """Dictionary-based factory for instances of type Domain

        :param updater: An instance of the Updater class
        :type updater: Updater
        :param router: An instance of the Router class, representing the home router
        :type router: Router
        :param dns_providers: An instance of a DNSProvider, used to update the domain records
        :type dns_providers: Dict[str, &#39;DNSProvider&#39;]
        :param domain_config: A dictionary holding the configuration for this domain
        :type domain_config: _type_
        :return: An instance of the Domain class
        :rtype: Domain
        """
        dns_provider = dns_providers[domain_config['dns-provider']]
        domain = Domain(
            updater,
            router,
            domain_config['name'],
            dns_provider,
            domain_config.get('delay', 0),
        )
        hosts_config = domain_config['hosts']
        for host_config in hosts_config:
            host = Host.from_config(router, host_config)
            domain.add_host(host)
        return domain

    def add_host(self, host: Host):
        """Add a Host instance to this domain

        :param host: An instance of Host to be added to this domain
        :type host: Host
        """
        self._host_list.append(host)

    def _read_from_cache(self):
        """Read data from common cache, e.g. datetime of last update for this domain
        """
        domain_cache = self._updater.get_cache_domain(self._domain_name)
        if KEY_LAST_UPDATE in domain_cache:
            self._last_update = domain_cache[KEY_LAST_UPDATE]

    def update(self, dry_run: bool = False):
        """Update this domain

        :param dry_run: If true, do not actually update the domain, defaults to False
        :type dry_run: bool, optional
        """
        if self._last_update is not None:
            time_diff = int(
                (datetime.datetime.now() - self._last_update).total_seconds()
            )
            if time_diff < self._delay:
                logging.info(
                    'Skipping updates for domain "%s" due to update delay', self._domain_name
                )
                return
        records_ipv4 = []
        records_ipv6 = []
        needs_update = False
        for host in self._host_list:
            if host.needs_update():
                needs_update = True
                dns_prefix = host.fqdn.removesuffix(self._domain_name).removesuffix('.')
                if host.host_ipv4 is not None:
                    record = DNSRecord(
                        hostname=dns_prefix, type='A', destination=str(host.host_ipv4)
                    )
                    records_ipv4.append(record)
                ipv6 = host.host_ipv6
                if ipv6 is not None:
                    record = DNSRecord(
                        hostname=dns_prefix, type='AAAA', destination=str(ipv6)
                    )
                    records_ipv6.append(record)
        # Update if at least one record changed
        if needs_update:
            logging.info('Updating domain: "%s"', self._domain_name)
            self._last_update = datetime.datetime.now()
            domain_cache = self._updater.get_cache_domain(self._domain_name)
            domain_cache[KEY_LAST_UPDATE] = self._last_update
            self._updater.update_cache_domain(self._domain_name, domain_cache)
            self._rebuild_domain_records_cache()
            for record in records_ipv4:
                current_record_id = self._find_record_id(record.hostname, 'A')
                if current_record_id is not None:
                    record.id = current_record_id
            for record in records_ipv6:
                current_record_id = self._find_record_id(record.hostname, 'AAAA')
                if current_record_id is not None:
                    record.id = current_record_id
            records = records_ipv4 + records_ipv6
            if not dry_run:
                self._dns_provider.update_domain(self, records)

    def _rebuild_domain_records_cache(self):
        """Rebuild the domain record cache from data fetched from the configure DNS provider
        """
        record_dict = {}
        records = self._dns_provider.fetch_domain(self)
        for record in records:
            hostname_dict = record_dict.get(record.hostname, {})
            hostname_dict[record.type] = record
            record_dict[record.hostname] = hostname_dict
        self._domain_record_dict = record_dict

    def _find_record_id(self, hostname, record_type)->Optional[DNSRecord]:
        """Find a specific record in the domain record cache if any

        :param hostname: Hostname to search for
        :type hostname: _type_
        :param record_type: The record type, i.e. A or AAAA record
        :type record_type: _type_
        :return: The DNS record if any
        :rtype: DNSRecord or None
        """
        if (
            hostname not in self._domain_record_dict or
            record_type not in self._domain_record_dict[hostname]
        ):
            return None
        return self._domain_record_dict[hostname][record_type].id

    @property
    def domain_name(self)->str:
        """Property holding the domain name (FQDN)

        :return: The domain name (FQDN)
        :rtype: str
        """
        return self._domain_name


class Router:
    """A class representing a home router"""

    _ipv4: Optional[IPAddress]
    """The IPv4 address of the router, if any"""
    _ipv6: Optional[IPAddress]
    """The IPv6 address of the router, if any"""

    def __init__(self, router_ipv4_config, router_ipv6_config):
        """Constructor of the Router class

        :param router_ipv4_config: The IPv4 configuration of the router
        :type router_ipv4_config: Dict
        :param router_ipv6_config: The IPv6 configuration of the router
        :type router_ipv6_config: Dict
        :raises Exception: _description_
        :raises Exception: _description_
        """
        self._ipv4 = None
        try:
            self._ipv4 = self._get_public_ipv4(router_ipv4_config)
        except Exception as exc:
            raise Exception(
                'Exception occurred while identifying public IPv4 address of the router'
            ) from exc
        # logging.info(f'Router has external IPv4: {self._ipv4}')
        self._ipv6 = None
        try:
            self._ipv6 = self._get_public_ipv6(router_ipv6_config)
        except Exception as exc:
            raise Exception(
                'Exception occurred while identifying public IPv6 address of the router'
            ) from exc
        # logging.info(f'Router has external IPv6: {self._ipv6}')

    @staticmethod
    def from_config(router_config):
        router_ipv4_config = router_config.get('ipv4', None)
        router_ipv6_config = router_config.get('ipv6', None)
        return Router(router_ipv4_config, router_ipv6_config)

    def _get_public_ipv4(self, ipv4_config) -> netaddr.IPAddress:
        if ipv4_config is None:
            return None
        if ipv4_config['method'] == 'web':
            url = ipv4_config['url']
            response = requests.get(url)
            if response:
                ipv4_candidate = response.text
                return util.get_valid_ip(ipv4_candidate)
            else:
                raise Exception(
                    f'Unable to determine external IPv4 of router through website {url}'
                )
        elif ipv4_config['method'] == 'wan':
            wan_interface_ipv4 = ipv4_config['wan_interface']
            ipv4_list = util.get_ipv4_addresses_linux(wan_interface_ipv4)
            # Return first address if any
            return None if len(ipv4_list) == 0 else ipv4_list[0]
        elif ipv4_config['method'] == 'fritzbox':
            fritzbox_config = ipv4_config['fritzbox']
            fritz_ip = fritzbox_config.get('address')
            fritz_tls = fritzbox_config.get('tls', False)
            try:
                fc = fritzconnection.FritzConnection(
                    address=fritz_ip, use_tls=fritz_tls
                )
                status = fritzconnection.lib.fritzstatus.FritzStatus(fc)
            except fritzconnection.core.exceptions.FritzConnectionException as exc:
                raise RouterNotReachableException(
                    'Unable to connect to Fritz!Box while querying external IPv4'
                ) from exc
            return util.get_valid_ip(status.external_ip)
        raise Exception('Did not find a supported method for getting the public Ipv4!')

    def _get_public_ipv6(self, ipv6_config) -> Optional[str]:
        if ipv6_config is None:
            return None
        if ipv6_config['method'] == 'web':
            url = ipv6_config['url']
            response = requests.get(url)
            if response:
                ipv6_candidate = response.text
                return util.get_valid_ip(ipv6_candidate)
            else:
                raise Exception(
                    f'Unable to determine external IPv6 of router through website {url}'
                )
        elif ipv6_config['method'] == 'wan':
            wan_interface_ipv6 = ipv6_config['wan_interface']
            ipv6_list = util.get_ipv6_addresses_linux(wan_interface_ipv6)
            # Return first address if any
            return None if len(ipv6_list) == 0 else ipv6_list[0]
        elif ipv6_config['method'] == 'fritzbox':
            fritzbox_config = ipv6_config['fritzbox']
            fritz_ip = fritzbox_config.get('address')
            fritz_tls = fritzbox_config.get('tls', False)
            try:
                fc = fritzconnection.FritzConnection(
                    address=fritz_ip, use_tls=fritz_tls
                )
                status = fritzconnection.lib.fritzstatus.FritzStatus(fc)
            except fritzconnection.core.exceptions.FritzConnectionException as exc:
                raise RouterNotReachableException(
                    'Unable to connect to Fritz!Box while querying external IPv6'
                ) from exc
            return util.get_valid_ip(status.external_ipv6)
        raise Exception('Did not find a supported method for getting the public Ipv6!')

    @property
    def ipv4(self):
        return self._ipv4

    @property
    def use_ipv4(self):
        return self._ipv4 is not None

    @property
    def ipv6(self):
        return self._ipv6

    @property
    def use_ipv6(self):
        return self._ipv6 is not None


class DNSProvider(ABC):
    pass

    @abstractmethod
    def fetch_domain(self, domain: Domain) -> List[DNSRecord]:
        """Abstract method for fetching domain data from the DNS provider

        Parameters
        ----------
        domain : Domain
            The domain object to fetch data from.

        Returns
        -------
        List[DNSRecord]
            A list of DNS records fetched from the DNS provider which could be updated.
        """

    @abstractmethod
    def update_domain(self, domain: Domain, records: List[DNSRecord]):
        """Abstract method for updating the provided list of records in the provided domain

        Parameters
        ----------
        domain : Domain
            The domain to update.
        records : List[DNSRecord]
            A list of DNS records to set in DNS of the provided domain
        """


class Netcup(DNSProvider):
    def __init__(self, userid, apikey, apipass):
        self._userid = userid
        self._apikey = apikey
        self._apipass = apipass

    @staticmethod
    def from_config(config: Dict[str, str]) -> 'Netcup':
        userid = int(config['userid'])
        apikey = config['apikey']
        apipass = config['apipass']
        return Netcup(userid, apikey, apipass)

    def fetch_domain(self, domain: Domain) -> List[DNSRecord]:
        with Client(self._userid, self._apikey, self._apipass) as api:
            # fetch records
            return api.dns_records(domain.domain_name)

    def update_domain(self, domain: Domain, records: List[DNSRecord]):
        with Client(self._userid, self._apikey, self._apipass) as api:
            # Update records
            logging.info(
                f'Updating the following DNS records in domain {domain.domain_name}:'
            )
            for record in records:
                logging.info(record)
            api.update_dns_records(domain.domain_name, records)


class Updater:
    _config: Dict[str, Any]
    _cache_file: Optional[Path]
    _cache: Dict[str, Any]
    _dns_providers: Dict[str, DNSProvider]
    _domains: List[Domain]

    def __init__(self, cache_dir: Path = None):
        self._cache_dir = cache_dir
        self._dns_providers = {}
        self._domains = []
        self._cache = {}

    @staticmethod
    def from_config(config) -> 'Updater':
        cache_dir = None
        common_config = config.get('common', None)
        if common_config is not None:
            cache_dir_str = common_config.get('cache_dir', None)
            if cache_dir_str is not None:
                cache_dir_candidate = Path(cache_dir_str)
                if cache_dir_candidate.exists() or cache_dir_candidate.is_dir():
                    cache_dir = cache_dir_candidate
        updater = Updater(cache_dir)
        updater.read_cache()

        try:
            dns_provider_list = config['dns-providers']
            for provider in dns_provider_list:
                name = provider['name']
                provider_type = provider['type'].lower()
                if provider_type == 'netcup':
                    updater.add_dns_provider(name, Netcup.from_config(provider))
            # Initialize router
            router = Router.from_config(config['router'])
            # Initialize domains
            for domain_config_dict in config['domains']:
                domain = Domain.from_config(
                    updater, router, updater.dns_providers, domain_config_dict
                )
                updater.add_domain(domain)
        except RouterNotReachableException as exc:
            logging.error(exc)
            raise Exception('Unable to initialize Updater') from exc
        return updater

    def add_dns_provider(self, name: str, dns_provider: DNSProvider):
        self._dns_providers[name] = dns_provider

    @property
    def dns_providers(self):
        return self._dns_providers

    def add_domain(self, domain: Domain):
        self._domains.append(domain)

    @property
    def domains(self):
        return self._domains

    @property
    def cache_dir(self):
        return self._cache_dir

    @cache_dir.setter
    def cache_dir(self, cache_dir: Path):
        self._cache_dir = cache_dir

    def read_cache(self):
        if self._cache_dir is None:
            return
        self._cache_file = self._cache_dir / Path(CACHE_FILE_NAME)
        if self._cache_file is not None and self._cache_file.exists():
            with open(self._cache_file, 'r') as f:
                self._cache = yaml.safe_load(f)
                if self._cache is None or self._cache == '':
                    self._cache = {}

    def write_cache(self):
        if self._cache_file is not None:
            with open(self._cache_file, 'w') as f:
                yaml.dump(self._cache, f)

    def get_cache_domain(self, domain_name: str) -> Dict:
        return self._cache.get(domain_name, {})

    def update_cache_domain(self, domain: str, domain_cache):
        self._cache[domain] = domain_cache
        self.write_cache()

    def update(self, dry_run: bool = False) -> int:
        for domain in self._domains:
            domain.update(dry_run)
        return 0

import datetime
from pathlib import Path
from typing import Any, Final, List, Dict, Optional, Set
import netaddr  # type: ignore
import yaml
import dns.resolver
from netaddr import IPAddress
import requests
import logging
from nc_dnsapi import Client, DNSRecord  # type: ignore
from abc import ABC, abstractmethod
from . import util
from .schemata import get_config_file_schema


class NetworkAddressException(Exception):
    pass


class RouterNotReachableException(Exception):
    pass


class Host:
    _name: str
    _router: "Router"
    _current_ipv4: Optional[IPAddress] = None
    _current_ipv6_set: Set[IPAddress] = set()
    _target_ipv4: Optional[IPAddress] = None
    _target_ipv6_set: Set[IPAddress] = set()

    def __init__(self, router: "Router", host_config):
        self._name = host_config["name"]
        self._fqdn = host_config["fqdn"]
        self._router = router
        public_ip_methods = host_config["public_ip_methods"]
        if "ipv4" in public_ip_methods:
            self._get_current_ipv4()
            self._get_target_ipv4(public_ip_methods["ipv4"])
        if "ipv6" in public_ip_methods:
            self._get_current_ipv6()
            self._get_target_ipv6(public_ip_methods["ipv6"])

    def _get_current_ipv4(self):
        # Get current address
        try:
            result = dns.resolver.resolve(self._fqdn, rdtype=dns.rdatatype.A)
            if len(result.rrset) > 0:
                self._current_ipv4 = result.rrset[0].address
        except Exception:
            self._current_ipv4 = None

    def _get_current_ipv6(self):
        # Get current address
        addresses = set()
        try:
            result = dns.resolver.resolve(self._fqdn, rdtype=dns.rdatatype.AAAA)
            for address in result.rrset:
                if util.is_public_ipv6(address):
                    addresses.add(address)
            self._current_ipv6_set = addresses
        except Exception:
            self._current_ipv6_set = {}

    def _get_target_ipv4(self, method: str):
        address = None
        if method == "router":
            address = self._router.ipv4
        elif method == "local_dns":
            try:
                result = dns.resolver.resolve(self._name, rdtype=dns.rdatatype.A)
                if result.rrset is not None and len(result.rrset) > 0:
                    address = result.rrset[0].address
            except Exception:
                raise Exception(f"Local hostname not found: {self._name}")

        if address is not None:
            self._target_ipv4 = IPAddress(address)

    def _get_target_ipv6(self, method: str):
        addresses = set(IPAddress)
        if method == "router":
            addresses.add(self._router.ipv6)
        elif method == "local_dns":
            try:
                result = dns.resolver.resolve(self._name, rdtype=dns.rdatatype.AAAA)
                if result.rrset is None:
                    return
                for address_result in result.rrset:
                    address_candidate = IPAddress(address_result.address)
                    if util.is_public_ipv6(address_candidate):
                        addresses.add(address_candidate)
            except Exception:
                raise Exception(f"Local hostname not found: {self._name}")
        if len(addresses) > 0:
            self._target_ipv6_set = addresses

    def needs_update(self) -> bool:
        update = False
        if self._target_ipv4 is not None:
            if self._current_ipv4 is None:
                update = True
            elif self._current_ipv4 != self._target_ipv4:
                update = True
        if len(self._target_ipv6_set) > 0:
            # Find disjoint set. An update is only required if none of the current
            # addresses is in the set of target addresses
            common_addresses = self._current_ipv6_set & self._target_ipv6_set
            if len(common_addresses) == 0:
                update = True
        return update

    def get_updated_ipv4_record(self):
        return self._target_ipv4

    def get_updated_ipv6_record(self):
        if self._target_ipv6_set is None or len(self._target_ipv6_set) == 0:
            return None
        return list(self._target_ipv6_set)[0]

    @property
    def name(self):
        return self._name

    @property
    def fqdn(self):
        return self._fqdn


class Domain:
    _updater: "Updater"
    _delay: int = 0
    _target_records_ipv4: Dict[str, netaddr.IPAddress] = {}
    _target_records_ipv6: Dict[str, netaddr.IPAddress] = {}
    _router: "Router"
    _domain_name: str
    _dns_provider: "DNSProvider"
    _last_update: Optional[datetime.datetime] = None
    _key_domains: Final[str] = "domains"
    _key_last_update: Final[str] = "last_updated"
    _host_list: List[Host] = []

    def __init__(
        self,
        updater: "Updater",
        router,
        dns_providers: Dict[str, "DNSProvider"],
        domain_config,
    ):
        self._updater = updater
        self._router = router
        self._domain_name = domain_config["name"]
        self._dns_provider = dns_providers[domain_config["dns-provider"]]
        self._delay = domain_config.get("delay", 0)
        hosts_config = domain_config["hosts"]
        for host_config in hosts_config:
            host = Host(router, host_config)
            self._host_list.append(host)
        self._read_from_cache()

    def _read_from_cache(self):
        domain_cache = self._updater.get_cache_domain(self._domain_name)
        if self._key_last_update in domain_cache:
            self._last_update = domain_cache[self._key_last_update]

    def update(self, dry_run: bool = False):
        if self._last_update is not None:
            time_diff = int(
                (datetime.datetime.now() - self._last_update).total_seconds()
            )
            if time_diff < self._delay:
                logging.info(
                    f'Skipping updates for domain "{self._domain_name}" due to update delay'
                )
                return
        records_ipv4 = []
        records_ipv6 = []
        needs_update = False
        for host in self._host_list:
            if host.needs_update():
                needs_update = True
                dns_prefix = host.fqdn.removesuffix(self._domain_name).removesuffix(".")
                ipv4 = host.get_updated_ipv4_record()
                if ipv4 is not None:
                    record = DNSRecord(
                        hostname=dns_prefix, type="A", destination=str(ipv4)
                    )
                    records_ipv4.append(record)
                ipv6 = host.get_updated_ipv6_record()
                if ipv6 is not None:
                    record = DNSRecord(
                        hostname=dns_prefix, type="AAAA", destination=str(ipv6)
                    )
                    records_ipv6.append(record)
        # Update if at least one record changed
        if needs_update:
            logging.info(f"Updating domain: {self._domain_name}")
            self._last_update = datetime.datetime.now()
            domain_cache = self._updater.get_cache_domain(self._domain_name)
            domain_cache[self._key_last_update] = self._last_update
            self._updater.update_cache_domain(self._domain_name, domain_cache)
            self._rebuild_domain_records_cache()
            for record in records_ipv4:
                current_record_id = self._find_record_id(record.hostname, "A")
                if current_record_id is not None:
                    record.id = current_record_id
            for record in records_ipv6:
                current_record_id = self._find_record_id(record.hostname, "AAAA")
                if current_record_id is not None:
                    record.id = current_record_id
            records = records_ipv4 + records_ipv6
            if not dry_run:
                self._dns_provider.update_domain(self, records)

    def _rebuild_domain_records_cache(self):
        record_dict = {}
        records = self._dns_provider.fetch_domain(self)
        for record in records:
            hostname_dict = record_dict.get(record.hostname, {})
            hostname_dict[record.type] = record
            record_dict[record.hostname] = hostname_dict
        self._domain_record_dict = record_dict

    def _find_record_id(self, hostname, record_type):
        if (
            hostname not in self._domain_record_dict
            or record_type not in self._domain_record_dict[hostname]
        ):
            return None
        return self._domain_record_dict[hostname][record_type].id

    @property
    def domain_name(self):
        return self._domain_name


class Router:
    def _get_public_ipv4(self, ipv4_config) -> netaddr.IPAddress:
        if ipv4_config["method"] == "web":
            url = ipv4_config["url"]
            response = requests.get(url)
            if response:
                ipv4_candidate = response.text
                return util.get_valid_ip(ipv4_candidate)
            else:
                raise Exception(
                    f"Unable to determine external IPv4 of router through website {url}"
                )
        elif ipv4_config["method"] == "wan":
            self._wan_interface_ipv4 = ipv4_config["wan_interface"]
            ipv4_list = util.get_ipv4_addresses_linux(self._wan_interface_ipv4)
            # Return first address if any
            return None if len(ipv4_list) == 0 else ipv4_list[0]
        elif ipv4_config["method"] == "fritzbox":
            from fritzconnection import FritzConnection  # type: ignore
            from fritzconnection.lib.fritzstatus import FritzStatus  # type: ignore
            from fritzconnection.core.exceptions import FritzConnectionException  # type: ignore

            fritzbox_config = ipv4_config["fritzbox"]
            fritz_ip = fritzbox_config.get("address")
            fritz_tls = fritzbox_config.get("tls", False)
            try:
                fc = FritzConnection(address=fritz_ip, use_tls=fritz_tls)
                status = FritzStatus(fc)
            except FritzConnectionException as exc:
                raise RouterNotReachableException(
                    "Unable to connect to Fritz!Box"
                ) from exc
            return status.external_ip
        return None

    def _get_public_ipv6(self, ipv6_config) -> Optional[str]:
        if ipv6_config["method"] == "web":
            url = ipv6_config["url"]
            response = requests.get(url)
            if response:
                ipv6_candidate = response.text
                return util.get_valid_ip(ipv6_candidate)
            else:
                raise Exception(
                    f"Unable to determine external IPv6 of router through website {url}"
                )
        elif ipv6_config["method"] == "wan":
            self._wan_interface_ipv6 = ipv6_config["wan_interface"]
            ipv6_list = util.get_ipv6_addresses_linux(self._wan_interface_ipv6)
            # Return first address if any
            return None if len(ipv6_list) == 0 else ipv6_list[0]
        return None

    def __init__(self, config):
        router_config = config["router"]
        router_ipv4_config = router_config["ipv4"]
        router_ipv6_config = router_config["ipv6"]
        self._use_ipv4 = router_ipv4_config.get("enabled", False)
        self._use_ipv6 = router_ipv6_config.get("enabled", False)
        self._ipv4 = None
        self._ipv6 = None
        self._wan_interface_ipv4 = None
        self._wan_interface_ipv6 = None
        if self._use_ipv4:
            try:
                self._ipv4 = self._get_public_ipv4(router_config["ipv4"])
            except RouterNotReachableException as exc:
                raise exc
            logging.info(f"Router has external IPv4: {self._ipv4}")
        if self._use_ipv6:
            try:
                self._ipv6 = self._get_public_ipv6(router_config["ipv6"])
            except RouterNotReachableException as exc:
                raise exc
            logging.info(f"Router has external IPv6: {self._ipv6}")

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

    @abstractmethod
    def update_domain(self, domain: Domain, records: List[DNSRecord]):
        pass


class Netcup(DNSProvider):
    def __init__(self, config):
        self._userid = int(config["userid"])
        self._apikey = config["apikey"]
        self._apipass = config["apipass"]

    def fetch_domain(self, domain: Domain) -> List[DNSRecord]:
        with Client(self._userid, self._apikey, self._apipass) as api:
            # fetch records
            return api.dns_records(domain.domain_name)
        return []

    def update_domain(self, domain: Domain, records: List[DNSRecord]):
        with Client(self._userid, self._apikey, self._apipass) as api:
            # Update records
            logging.info(
                f"Updating the following DNS records in domain {domain.domain_name}:"
            )
            for record in records:
                logging.info(record)
            api.update_dns_records(domain.domain_name, records)


class Updater:
    _config: Dict[str, Any]
    _cache_file: Optional[Path] = None
    _cache: Dict[str, Any]

    def __init__(self, config):
        self._config = config
        if "common" in self._config:
            if "cache_dir" in self._config["common"]:
                cache_dir_str = self._config["common"]["cache_dir"]
                cache_dir = Path(cache_dir_str)
                if cache_dir.exists() or cache_dir.is_dir():
                    self._cache_file = cache_dir / "cache.json"
                    self._read_cache()

    def _read_cache(self):
        if self._cache_file is not None and self._cache_file.exists():
            with open(self._cache_file, "r") as f:
                self._cache = yaml.safe_load(f)
                if self._cache is None:
                    self._cache = {}

    def _write_cache(self):
        if self._cache_file is not None:
            with open(self._cache_file, "w") as f:
                yaml.dump(self._cache, f)

    def get_cache_domain(self, domain: str) -> Dict:
        return self._cache.get(domain, {})

    def update_cache_domain(self, domain: str, domain_cache):
        self._cache[domain] = domain_cache
        self._write_cache()

    def update(self, dry_run: bool = False) -> int:
        try:
            dns_provider_list = self._config["dns-providers"]
            dns_providers: Dict[str, DNSProvider] = {}
            for provider in dns_provider_list:
                name = provider["name"]
                provider_type = provider["type"].lower()
                if provider_type == "netcup":
                    dns_providers[name] = Netcup(provider)
            router = Router(self._config)
            domain_config_list = self._config["domains"]
            for domain_config_dict in domain_config_list:
                domain = Domain(self, router, dns_providers, domain_config_dict)
                domain.update(dry_run)
        except RouterNotReachableException as e:
            logging.error(e)
            return 1
        return 0
# Licensed under the GPL v3: https://www.gnu.org/licenses/gpl-3.0
# For details: https://github.com/ethaden/multidyndnscli/blob/main/LICENSE
# Copyright (c) https://github.com/ethaden/multidyndnscli/blob/main/CONTRIBUTORS.md

"""Utility methods for multidyndnscli"""
from typing import List
import netaddr  # type: ignore
import netifaces  # type: ignore

ipv4_private_net_192_168 = netaddr.IPNetwork("192.168.0.0/16")
ipv4_private_net_172_16 = netaddr.IPNetwork("172.16.0.0/12")
ipv4_private_net_10 = netaddr.IPNetwork("172.16.0.0/12")
# Unique Local Addresses (ULAs)
ipv6_private_net_fc = netaddr.IPNetwork("fc00::/7")
# Management addresses
ipv6_private_net_fd = netaddr.IPNetwork("fd00::/8")
ipv6_private_net_fe = netaddr.IPNetwork(
    "fe80::/10"
)  # Addresses used for autoconfiguration


def get_valid_ip(address: str) -> netaddr.IPAddress:
    """Return a valid IP address from the provided string if possible

    :param address: String containing an IP address
    :type address: str
    :return: A valid IP address instance, if parsing was successful
    :rtype: netaddr.IPAddress
    """
    addr = netaddr.IPAddress(address)
    return addr


def is_public_ipv4(address: netaddr.IPAddress) -> bool:
    """Check whether or not the provided IP address is a public IPv4 address

    :param address: IP address to check
    :type address: netaddr.IPAddress
    :return: True if address is a public IPv4 address, otherwise False
    :rtype: bool
    """
    if address.version != 4:
        return False
    return not (
        (address in ipv4_private_net_10)
        or (address in ipv4_private_net_172_16)
        or (address in ipv4_private_net_192_168)
    )


def get_ipv4_addresses_linux(
    interface: str, public_only: bool = True
) -> List[netaddr.IPAddress]:
    """Find all/public IPv4 addresses of the given interfaces on Linux
    
    :param interface: The network interface to use
    :type interface: str
    :param public_only: If True, gets only public IPv4 addresses. Otherwise: Get all
    :return: A list of IP addresses
    :rtype: List[netaddr.IPAddress]
    """
    addrs = netifaces.ifaddresses(interface)
    address_string_list = [addr['addr'] for addr in addrs[netifaces.AF_INET]]
    address_list = [get_valid_ip(address) for address in address_string_list]
    if public_only:
        return [addr for addr in address_list if is_public_ipv4(addr)]
    return address_list


def is_public_ipv6(address: netaddr.IPAddress) -> bool:
    """Check whether or not the provided IP address is a public IPv6 address

    :param address: IP address to check
    :type address: netaddr.IPAddress
    :return: True if address is a public IPv6 address, otherwise False
    :rtype: bool
    """
    if address.version != 6:
        return False
    return not (
        (address in ipv6_private_net_fc)
        or (address in ipv6_private_net_fd)
        or (address in ipv6_private_net_fe)
    )


def get_ipv6_addresses_linux(interface: str, public_only: bool = True) -> List[str]:
    """Find all/public IPv6 addresses of the given interfaces on Linux
    
    :param interface: The network interface to use
    :type interface: str
    :param public_only: If True, gets only public IPv6 addresses. Otherwise: Get all
    :return: A list of IP addresses
    :rtype: List[netaddr.IPAddress]
    """
    addrs = netifaces.ifaddresses(interface)
    # Note, that addresses used for autoconfiguration have the format
    # "ipv6_adddr%interface_name"
    if netifaces.AF_INET6 not in addrs:
        return []
    address_string_list = [
        addr["addr"].split("%")[0] for addr in addrs[netifaces.AF_INET6]
    ]
    addresses_list = [get_valid_ip(address) for address in address_string_list]
    if public_only:
        return [addr for addr in addresses_list if is_public_ipv6(addr)]
    return addresses_list

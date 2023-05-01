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
    addr = netaddr.IPAddress(address)
    return addr


def is_public_ipv4(address: netaddr.IPAddress) -> bool:
    return not (
        (address in ipv4_private_net_10)
        or (address in ipv4_private_net_172_16)
        or (address in ipv4_private_net_192_168)
    )


def get_ipv4_addresses_linux(
    interface: str, public_only: bool = True
) -> List[netaddr.IPAddress]:
    """
    Find all IPv6 addresses of the given interfaces.
    """

    addrs = netifaces.ifaddresses(interface)
    address_string_list = [addr["addr"] for addr in addrs[netifaces.AF_INET]]
    address_list = [get_valid_ip(address) for address in address_string_list]
    if public_only:
        return [addr for addr in address_list if is_public_ipv4(addr)]
    return address_list


def is_public_ipv6(address: netaddr.IPAddress) -> bool:
    return not (
        (address in ipv6_private_net_fc)
        or (address in ipv6_private_net_fd)
        or (address in ipv6_private_net_fe)
    )


def get_ipv6_addresses_linux(interface: str, public_only: bool = True) -> List[str]:
    """
    Find all IPv6 addresses of the given interfaces.
    """

    addrs = netifaces.ifaddresses(interface)
    # Note, that addresses used for autoconfiguration have the format
    # "ipv6_adddr%interface_name"
    address_string_list = [
        addr["addr"].split("%")[0] for addr in addrs[netifaces.AF_INET6]
    ]
    addresses_list = [get_valid_ip(address) for address in address_string_list]
    if public_only:
        return [addr for addr in addresses_list if is_public_ipv6(addr)]
    return addresses_list


# def get_public_ipv6(hostname: str) -> netaddr.IPAddress:
#     result_list = dns.resolver.query(hostname, "AAAA")
#     # Remove local ones
#     for val in result_list:
#         if (
#             not val.address.startswith("fd")
#             and not val.address.startswith("fe")
#             and not val.address.startswith("fc")
#         ):
#             return get_valid_ip(val.address)
#     return None

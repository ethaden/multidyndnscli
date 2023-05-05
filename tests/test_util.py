from netaddr import IPAddress
import pytest
from multidyndnscli import util
import netifaces

testdata_invalid_ip = [('1.2.3.4.5'), (':abcde::')]

testdata_ipv4 = [
    ('192.168.0.1', False),
    ('192.168.25.23', False),
    ('8.8.8.8', True),
    ('172.16.0.1', False),
    ('fe80::ffff:ffff:ffff:ffff', False),
    ('2a02:8000:a000:f000:ffff:ffff:ffff:ffff', False)
]

testdata_ipv6 = [
    ('fe80::ffff:ffff:ffff:ffff', False),
    ('fd00::aaaa:bbbb:cccc:dddd', False),
    ('fc00::aaaa:bbbb:cccc:dddd', False),
    ('2a02:8000:a000:f000:ffff:ffff:ffff:ffff', True),
    ('2a02:8000:a000:f000:0:0:0:0', True),
    ('2a02:8000:a000:f000:0:0:0:1', True),
    ('192.168.0.1', False),
    ('8.8.8.8', False),
]

testdata_linux_ipv6 = [
    ([{'addr': '1.2.3.4'}, {'addr': '192.168.0.1'}], [IPAddress('1.2.3.4'), IPAddress('192.168.0.1')]),
    ([{'addr': '4.3.2.1'}, {'addr': '8.8.8.8'}], [IPAddress('4.3.2.1'), IPAddress('8.8.8.8')]),
]

testdata_linux_ipv6_public = [
    ([{'addr': '1.2.3.4'}, {'addr': '192.168.0.1'}], [IPAddress('1.2.3.4')]),
    ([{'addr': '4.3.2.1'}, {'addr': '8.8.8.8'}], [IPAddress('4.3.2.1'), IPAddress('8.8.8.8')]),
]

@pytest.mark.parametrize('address', testdata_invalid_ip)
def test_get_exception_for_invalid_ip(address):
    with pytest.raises(Exception):
        util.get_valid_ip(address)


@pytest.mark.parametrize('address, expected', testdata_ipv4)
def test_is_public_ipv4(address, expected):
    addr = util.get_valid_ip(address)
    assert util.is_public_ipv4(addr) == expected


@pytest.mark.parametrize('address, expected', testdata_ipv6)
def test_is_public_ipv6(address, expected):
    addr = util.get_valid_ip(address)
    assert util.is_public_ipv6(addr) == expected

@pytest.mark.parametrize('addresses, expected', testdata_linux_ipv6)
def test_get_ipv4_addresses_linux(addresses, expected, mocker):
    mocker.patch('netifaces.ifaddresses', return_value={netifaces.AF_INET: addresses})
    addrs = util.get_ipv4_addresses_linux('eth0', False)
    assert addrs == expected

@pytest.mark.parametrize('addresses, expected', testdata_linux_ipv6_public)
def test_get_ipv4_addresses_linux_public_only(addresses, expected, mocker):
    mocker.patch('netifaces.ifaddresses', return_value={netifaces.AF_INET: addresses})
    addrs = util.get_ipv4_addresses_linux('eth0', True)
    assert addrs == expected

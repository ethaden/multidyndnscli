import pytest
from netaddr import IPAddress
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

testdata_linux_ipv4 = [
    ({netifaces.AF_INET: [{'addr': '1.2.3.4'}, {'addr': '192.168.0.1'}], 
            netifaces.AF_INET6: [{'addr': '2a02:8000:a000:f000:ffff:ffff:ffff:ffff'}]}, 
        [IPAddress('1.2.3.4'), IPAddress('192.168.0.1')]),
    ({netifaces.AF_INET: [{'addr': '8.8.8.8'}, {'addr': '192.168.0.1'}], 
            netifaces.AF_INET6: [{'addr': '2a02:8000:a000:f000:ffff:ffff:ffff:ffff'}]}, 
        [IPAddress('8.8.8.8'), IPAddress('192.168.0.1')]),
]

testdata_linux_ipv4_public = [
    ({netifaces.AF_INET: [{'addr': '1.2.3.4'}, {'addr': '192.168.0.1'}], 
            netifaces.AF_INET6: [{'addr': '2a02:8000:a000:f000:ffff:ffff:ffff:ffff'}]}, 
        [IPAddress('1.2.3.4')]),
    ({netifaces.AF_INET: [{'addr': '8.8.8.8'}, {'addr': '192.168.0.1'}], 
            netifaces.AF_INET6: [{'addr': '2a02:8000:a000:f000:ffff:ffff:ffff:ffff'}]}, 
        [IPAddress('8.8.8.8')]),
]

testdata_linux_ipv6 = [
    ({netifaces.AF_INET: [{'addr': '1.2.3.4'}, {'addr': '192.168.0.1'}], 
            netifaces.AF_INET6: [{'addr': '2a02:8000:a000:f000:ffff:ffff:ffff:ffff'}, {'addr': 'fe80::ffff:ffff:ffff:ffff'}]}, 
        [IPAddress('2a02:8000:a000:f000:ffff:ffff:ffff:ffff'), IPAddress('fe80::ffff:ffff:ffff:ffff')]),
    ({netifaces.AF_INET: [{'addr': '8.8.8.8'}, {'addr': '192.168.0.1'}], 
            netifaces.AF_INET6: [{'addr': '2a02:8000:a000:f000:ffff:ffff:ffff:ffff'}]}, 
        [IPAddress('2a02:8000:a000:f000:ffff:ffff:ffff:ffff')]),
]

testdata_linux_ipv6_public = [
    ({netifaces.AF_INET: [{'addr': '1.2.3.4'}, {'addr': '192.168.0.1'}], 
            netifaces.AF_INET6: [{'addr': '2a02:8000:a000:f000:ffff:ffff:ffff:ffff'}, {'addr': 'fe80::ffff:ffff:ffff:ffff'}]}, 
        [IPAddress('2a02:8000:a000:f000:ffff:ffff:ffff:ffff')]),
    ({netifaces.AF_INET: [{'addr': '8.8.8.8'}, {'addr': '192.168.0.1'}], 
            netifaces.AF_INET6: [{'addr': '2a02:8000:a000:f000:ffff:ffff:ffff:ffff'}]}, 
        [IPAddress('2a02:8000:a000:f000:ffff:ffff:ffff:ffff')]),
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

@pytest.mark.parametrize('addresses, expected', testdata_linux_ipv4)
def test_get_ipv4_addresses_linux(addresses, expected, mocker):
    mocker.patch('netifaces.ifaddresses', return_value=addresses)
    addrs = util.get_ipv4_addresses_linux('eth0', False)
    assert addrs == expected

@pytest.mark.parametrize('addresses, expected', testdata_linux_ipv4_public)
def test_get_ipv4_addresses_linux_public_only(addresses, expected, mocker):
    mocker.patch('netifaces.ifaddresses', return_value=addresses)
    addrs = util.get_ipv4_addresses_linux('eth0', True)
    assert addrs == expected

@pytest.mark.parametrize('addresses, expected', testdata_linux_ipv6)
def test_get_ipv6_addresses_linux(addresses, expected, mocker):
    mocker.patch('netifaces.ifaddresses', return_value=addresses)
    addrs = util.get_ipv6_addresses_linux('eth0', False)
    assert addrs == expected

@pytest.mark.parametrize('addresses, expected', testdata_linux_ipv6_public)
def test_get_ipv6_addresses_linux_public_only(addresses, expected, mocker):
    mocker.patch('netifaces.ifaddresses', return_value=addresses)
    addrs = util.get_ipv6_addresses_linux('eth0', True)
    assert addrs == expected

def test_get_ipv6_addresses_linux_no_ipv6_networking(mocker):
    mocker.patch('netifaces.ifaddresses', return_value={})
    addrs = util.get_ipv6_addresses_linux('eth0', False)
    assert addrs == []

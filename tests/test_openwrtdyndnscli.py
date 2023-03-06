import pytest
import netaddr
import openwrtdyndnscli

testdata_ipv4 = [
    ('192.168.0.1', False),
    ('192.168.25.23', False),
    ('8.8.8.8', True),
    ('172.16.0.1', False),
]

testdata_ipv6 = [
    ('fe80::ffff:ffff:ffff:ffff', False),
    ('fd00::aaaa:bbbb:cccc:dddd', False),
    ('fc00::aaaa:bbbb:cccc:dddd', False),
    ('2a02:8000:a000:f000:ffff:ffff:ffff:ffff', True),
    ('2a02:8000:a000:f000:0:0:0:0', True),
    ('2a02:8000:a000:f000:0:0:0:1', True),
]


@pytest.mark.parametrize("address, expected", testdata_ipv4)
def test_is_public_ipv4(address, expected):
    assert openwrtdyndnscli.is_public_ipv4(address) == expected

@pytest.mark.parametrize("address, expected", testdata_ipv6)
def test_is_public_ipv6(address, expected):
    assert openwrtdyndnscli.is_public_ipv6(address) == expected

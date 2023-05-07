import dns
from netaddr import IPAddress
import pytest
import multidyndnscli

testdata_host_config_target_address_from_router = {
    'name': 'test-name',
    'fqdn': 'test-fqdn',
    'public_ip_methods': {
        'ipv4': 'router',
        'ipv6': 'router'
    }
}

testdata_host_config_target_address_from_local_dns = {
    'name': 'test-name',
    'fqdn': 'test-fqdn',
    'public_ip_methods': {
        'ipv4': 'local_dns',
        'ipv6': 'local_dns'
    }
}


testdata_ipv4 = '1.2.3.4'
testdata_ipv6 = '2a02:8000:a000:f000:ffff:ffff:ffff:ffff'

def test_class_host_init_target_addresses_from_router(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address= testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address= testdata_ipv6
    dns_resolver_mock = mocker.patch('dns.resolver.resolve', side_effect=
            lambda fqdn, rdtype: resolved_ipv4 if rdtype==dns.rdatatype.A else resolved_ipv6)

    host = multidyndnscli.Host(router, testdata_host_config_target_address_from_router)
    assert host._name == testdata_host_config_target_address_from_router['name']
    assert host._fqdn == testdata_host_config_target_address_from_router['fqdn']
    assert host._current_ipv4 == IPAddress(testdata_ipv4)
    assert host._current_ipv6_set == {IPAddress(testdata_ipv6)}
    assert host._target_ipv4 == IPAddress(testdata_ipv4)
    assert host._target_ipv6_set == {IPAddress(testdata_ipv6)}

def test_class_host_init_target_addresses_from_local_dns(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address= testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address= testdata_ipv6
    dns_resolver_mock = mocker.patch('dns.resolver.resolve', side_effect=
            lambda fqdn, rdtype: resolved_ipv4 if rdtype==dns.rdatatype.A else resolved_ipv6)

    host = multidyndnscli.Host(router, testdata_host_config_target_address_from_local_dns)
    assert host._name == testdata_host_config_target_address_from_local_dns['name']
    assert host._fqdn == testdata_host_config_target_address_from_local_dns['fqdn']
    assert host._current_ipv4 == IPAddress(testdata_ipv4)
    assert host._current_ipv6_set == {IPAddress(testdata_ipv6)}
    assert host._target_ipv4 == IPAddress(testdata_ipv4)
    assert host._target_ipv6_set == {IPAddress(testdata_ipv6)}

def test_class_host_init_exception_for_resolving_current_ips(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address= testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address= testdata_ipv6
    dns_resolver_mock = mocker.patch('dns.resolver.resolve', side_effect=
            lambda name, rdtype: 
                Exception('Test') if name==testdata_host_config_target_address_from_router['fqdn'] else
                    resolved_ipv4 if rdtype==dns.rdatatype.A else resolved_ipv6
        )
    host = multidyndnscli.Host(router, testdata_host_config_target_address_from_router)
    assert host._current_ipv4 is None
    assert len(host._current_ipv6_set) == 0

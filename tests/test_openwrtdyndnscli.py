import datetime
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, Mock, ANY, PropertyMock
import dns
from netaddr import IPAddress
import pytest
import multidyndnscli
from nc_dnsapi import DNSRecord, Client
import fritzconnection
import fritzconnection.lib.fritzstatus
import yaml

testdata_host_config_target_address_from_router = {
    'name': 'test-name',
    'fqdn': 'test-fqdn',
    'public_ip_methods': {'ipv4': 'router', 'ipv6': 'router'},
}

testdata_host_config_target_address_from_local_dns = {
    'name': 'test-name',
    'fqdn': 'test-fqdn',
    'public_ip_methods': {'ipv4': 'local_dns', 'ipv6': 'local_dns'},
}


testdata_ipv4 = '1.2.3.4'
testdata_other_ipv4 = '4.3.2.1'
testdata_ipv6 = '2a02:8000:a000:f000:ffff:ffff:ffff:ffff'
testdata_other_ipv6 = '2a02:8000:a000:ffff:ffff:ffff:ffff:ffff'
testdata_domain_name = 'example.invalid'
testdata_domain_name_other = 'other-example.invalid'
testdata_domain_config = {
    'name': testdata_domain_name,
    'delay': 23,
    'dns-provider': 'test',
    'hosts': [
        {
            'name': "server.lan",
            'fqdn': "server.home.test.invalid",
            'public_ip_methods': {'ipv4': "local_dns", 'ipv6': "local_dns"},
        }
    ],
}

testdata_update_record_ipv4 = [
    DNSRecord(hostname='test', type='A', destination=testdata_ipv4)
]

testdata_update_record_ipv4_with_id = [
    DNSRecord(hostname='test', type='A', destination=testdata_ipv4, id=23)
]

testdata_update_record_ipv6 = [
    DNSRecord(hostname='test', type='AAAA', destination=testdata_ipv6)
]

testdata_update_record_ipv6_with_id = [
    DNSRecord(hostname='test', type='AAAA', destination=testdata_ipv6, id=42)
]
testdata_update_records_combined = (
    testdata_update_record_ipv4 + testdata_update_record_ipv6
)
testdata_update_records_combined_with_ids = (
    testdata_update_record_ipv4_with_id + testdata_update_record_ipv6_with_id
)

testdata_router_method_web = {
    'ipv4': {'enabled': True, 'method': 'web', 'url': 'http://mock-me.invalid'},
    'ipv6': {'enabled': True, 'method': 'web', 'url': 'http://mock-me-v6.invalid'},
}

testdata_router_method_wan = {
    'ipv4': {
        'enabled': True,
        'method': 'wan',
        'wan_interface': 'eth9',
    },
    'ipv6': {'enabled': True, 'method': 'wan', 'wan_interface': 'eth9'},
}

testdata_router_method_fritz_box = {
    'ipv4': {
        'enabled': True,
        'method': "fritzbox",
        'fritzbox': {'address': '192.168.0.1', 'tls': False},
    },
    'ipv6': {
        'enabled': True,
        'method': "fritzbox",
        'fritzbox': {'address': '192.168.0.1', 'tls': False},
    },
}


testdata_router_method_illegal = {
    'ipv4': {'enabled': True, 'method': "illegal"},
    'ipv6': {'enabled': True, 'method': "illegal"},
}

testdata_dnsprovider_netcup = {
    'userid': '12345',
    'apikey': 'mykey',
    'apipass': 'mypass',
}

# Incomplete test data used with mocks
testdata_updater_config_mock = {
    'common': {
        'cache_dir': './test/cache_dir'
    },
    'dns-providers': [
        { 'name': 'dns-provider-name',
          'type': 'netcup'
        }
    ],
    'router': {
      'ipv4': {
          'enabled'
      }
    },
    'domains': [
        { 
            'name': 'test.invalid',
            'dns-provider': 'Netcup',
            'delay': 200
        }
    ]
}

def get_mock_ip_helper(mocker):
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_other_ipv6
    return resolved_ipv4, resolved_ipv6


def resolve_mock_helper(
    req_name,
    rdtype,
    host_name,
    fqdn,
    host_ipv4,
    host_ipv6_set,
    fqdn_dns_ipv4,
    fqdn_dns_ipv6_set,
):
    if req_name == host_name:
        if rdtype == dns.rdatatype.A:
            return host_ipv4
        else:
            return host_ipv6_set
    elif req_name == fqdn:
        if rdtype == dns.rdatatype.A:
            return fqdn_dns_ipv4
        else:
            return fqdn_dns_ipv6_set
    raise Exception(f'Unable to serve request to resolve name {req_name}')


def test_class_host_from_config(mocker):
    # router = MagicMock()
    # host = MagicMock(multidyndnscli.Host)
    # orig_create_method = multidyndnscli.Host.from_config
    # host_mock = mocker.patch('multidyndnscli.Host', return_value=host)
    # host_mock.from_config = orig_create_method
    # created_object = multidyndnscli.Host.from_config(router, testdata_host_config_target_address_from_router)
    # host_mock.assert_called_once_with(
    #     ANY,
    #     testdata_host_config_target_address_from_router['name'],
    #     testdata_host_config_target_address_from_router['fqdn'],
    #     testdata_host_config_target_address_from_router['public_ip_methods']['ipv4'],
    #     testdata_host_config_target_address_from_router['public_ip_methods']['ipv6']
    # )
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda fqdn, rdtype: resolved_ipv4
        if rdtype == dns.rdatatype.A
        else resolved_ipv6,
    )
    host = multidyndnscli.Host.from_config(
        router, testdata_host_config_target_address_from_router
    )
    assert host.name == testdata_host_config_target_address_from_router['name']
    assert host.fqdn == testdata_host_config_target_address_from_router['fqdn']
    assert host._current_fqdn_dns_ipv4 == IPAddress(testdata_ipv4)
    assert host._current_fqdn_dns_ipv6_set == {IPAddress(testdata_ipv6)}
    assert host.host_ipv4 == IPAddress(testdata_ipv4)
    assert host._host_ipv4 == IPAddress(testdata_ipv4)
    assert host.host_ipv6 == IPAddress(testdata_ipv6)
    assert host._host_ipv6_set == {IPAddress(testdata_ipv6)}


def test_class_host_init_target_addresses_from_router(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda fqdn, rdtype: resolved_ipv4
        if rdtype == dns.rdatatype.A
        else resolved_ipv6,
    )
    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_router['name'],
        testdata_host_config_target_address_from_router['fqdn'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv6'],
    )
    assert host.name == testdata_host_config_target_address_from_router['name']
    assert host.fqdn == testdata_host_config_target_address_from_router['fqdn']
    assert host._current_fqdn_dns_ipv4 == IPAddress(testdata_ipv4)
    assert host._current_fqdn_dns_ipv6_set == {IPAddress(testdata_ipv6)}
    assert host.host_ipv4 == IPAddress(testdata_ipv4)
    assert host._host_ipv4 == IPAddress(testdata_ipv4)
    assert host.host_ipv6 == IPAddress(testdata_ipv6)
    assert host._host_ipv6_set == {IPAddress(testdata_ipv6)}


def test_class_host_init_target_addresses_no_host_ipv6(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = None
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda fqdn, rdtype: resolved_ipv4
        if rdtype == dns.rdatatype.A
        else resolved_ipv6,
    )
    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_router['name'],
        testdata_host_config_target_address_from_router['fqdn'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv6'],
    )
    assert host.host_ipv6 == None


def test_class_host_init_target_addresses_from_local_dns(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda fqdn, rdtype: resolved_ipv4
        if rdtype == dns.rdatatype.A
        else resolved_ipv6,
    )
    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_local_dns['name'],
        testdata_host_config_target_address_from_local_dns['fqdn'],
        testdata_host_config_target_address_from_local_dns['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_local_dns['public_ip_methods']['ipv6'],
    )
    assert host._name == testdata_host_config_target_address_from_local_dns['name']
    assert host._fqdn == testdata_host_config_target_address_from_local_dns['fqdn']
    assert host._current_fqdn_dns_ipv4 == IPAddress(testdata_ipv4)
    assert host._current_fqdn_dns_ipv6_set == {IPAddress(testdata_ipv6)}
    assert host._host_ipv4 == IPAddress(testdata_ipv4)
    assert host._host_ipv6_set == {IPAddress(testdata_ipv6)}


def test_class_host_init_exception_for_resolving_current_ips(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda name, rdtype: resolve_mock_helper(
            name,
            rdtype,
            testdata_host_config_target_address_from_local_dns['name'],
            testdata_host_config_target_address_from_local_dns['fqdn'],
            resolved_ipv4,
            resolved_ipv6,
            Exception('Test'),
            Exception('Test'),
        ),
    )
    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_local_dns['name'],
        testdata_host_config_target_address_from_local_dns['fqdn'],
        testdata_host_config_target_address_from_local_dns['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_local_dns['public_ip_methods']['ipv6'],
    )
    assert host._current_fqdn_dns_ipv4 == None
    assert len(host._current_fqdn_dns_ipv6_set) == 0


def test_class_host_init_exception_for_resolving_host_ipv4(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda name, rdtype: resolve_mock_helper(
            name,
            rdtype,
            testdata_host_config_target_address_from_local_dns['name'],
            testdata_host_config_target_address_from_local_dns['fqdn'],
            Exception('Test'),
            resolved_ipv6,
            resolved_ipv4,
            resolved_ipv6,
        ),
    )
    with pytest.raises(Exception):
        host = multidyndnscli.Host(
            router,
            testdata_host_config_target_address_from_local_dns['name'],
            testdata_host_config_target_address_from_local_dns['fqdn'],
            testdata_host_config_target_address_from_local_dns['public_ip_methods'][
                'ipv4'
            ],
            testdata_host_config_target_address_from_local_dns['public_ip_methods'][
                'ipv6'
            ],
        )


def test_class_host_init_exception_for_resolving_host_ipv6(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda name, rdtype: resolve_mock_helper(  # lambda name, rdtype:
            name,
            rdtype,
            testdata_host_config_target_address_from_local_dns['name'],
            testdata_host_config_target_address_from_local_dns['fqdn'],
            resolved_ipv4,
            Exception('Test'),
            resolved_ipv4,
            resolved_ipv6,
        ),
    )
    with pytest.raises(Exception):
        host = multidyndnscli.Host(
            router,
            testdata_host_config_target_address_from_local_dns['name'],
            testdata_host_config_target_address_from_local_dns['fqdn'],
            testdata_host_config_target_address_from_local_dns['public_ip_methods'][
                'ipv4'
            ],
            testdata_host_config_target_address_from_local_dns['public_ip_methods'][
                'ipv6'
            ],
        )


def test_class_host_init_empty_target_ipv6_rrset(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    empty_ipv6_rrset = mocker.stub()
    empty_ipv6_rrset.rrset = None
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda name, rdtype: resolve_mock_helper(
            name,
            rdtype,
            testdata_host_config_target_address_from_local_dns['name'],
            testdata_host_config_target_address_from_local_dns['fqdn'],
            resolved_ipv4,
            empty_ipv6_rrset,
            resolved_ipv4,
            resolved_ipv6,
        ),
    )
    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_local_dns['name'],
        testdata_host_config_target_address_from_local_dns['fqdn'],
        testdata_host_config_target_address_from_local_dns['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_local_dns['public_ip_methods']['ipv6'],
    )
    assert len(host._host_ipv6_set) == 0


def test_class_host_needs_update_negative_case(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda fqdn, rdtype: resolved_ipv4
        if rdtype == dns.rdatatype.A
        else resolved_ipv6,
    )
    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_local_dns['name'],
        testdata_host_config_target_address_from_local_dns['fqdn'],
        testdata_host_config_target_address_from_local_dns['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_local_dns['public_ip_methods']['ipv6'],
    )
    assert host.needs_update() == False


def test_class_host_needs_update_missing_ipv4(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    #
    resolved_ipv4_empty_rrset = mocker.stub()
    resolved_ipv4_empty_rrset.rrset = []
    #
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda name, rdtype: resolve_mock_helper(
            name,
            rdtype,
            testdata_host_config_target_address_from_local_dns['name'],
            testdata_host_config_target_address_from_local_dns['fqdn'],
            resolved_ipv4,
            resolved_ipv6,
            resolved_ipv4_empty_rrset,
            resolved_ipv6,
        ),
    )
    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_router['name'],
        testdata_host_config_target_address_from_router['fqdn'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv6'],
    )
    assert host.needs_update() == True


def test_class_host_needs_update_wrong_ipv4(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_other_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda fqdn, rdtype: resolved_ipv4
        if rdtype == dns.rdatatype.A
        else resolved_ipv6,
    )

    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_router['name'],
        testdata_host_config_target_address_from_router['fqdn'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv6'],
    )
    assert host.needs_update() == True


def test_class_host_needs_update_missing_ipv6(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6_current_fqdn_dns_empty_rrset = mocker.stub()
    resolved_ipv6_current_fqdn_dns_empty_rrset.rrset = []
    resolved_ipv6_host = mocker.stub()
    resolved_ipv6_host.rrset = [mocker.stub()]
    resolved_ipv6_host.rrset[0].address = testdata_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda name, rdtype: resolve_mock_helper(
            name,
            rdtype,
            testdata_host_config_target_address_from_local_dns['name'],
            testdata_host_config_target_address_from_local_dns['fqdn'],
            resolved_ipv4,
            resolved_ipv6_host,
            resolved_ipv4,
            resolved_ipv6_current_fqdn_dns_empty_rrset,
        ),
    )

    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_router['name'],
        testdata_host_config_target_address_from_router['fqdn'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv6'],
    )
    assert host.needs_update() == True


def test_class_host_needs_update_wrong_ipv6(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_other_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda fqdn, rdtype: resolved_ipv4
        if rdtype == dns.rdatatype.A
        else resolved_ipv6,
    )

    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_router['name'],
        testdata_host_config_target_address_from_router['fqdn'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv6'],
    )
    assert host.needs_update() == True


def test_class_host_host_ipv4(mocker):
    router = mocker.stub()
    router.ipv4 = testdata_ipv4
    router.ipv6 = testdata_ipv6
    resolved_ipv4 = mocker.stub()
    resolved_ipv4.rrset = [mocker.stub()]
    resolved_ipv4.rrset[0].address = testdata_ipv4
    resolved_ipv6 = mocker.stub()
    resolved_ipv6.rrset = [mocker.stub()]
    resolved_ipv6.rrset[0].address = testdata_other_ipv6
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda fqdn, rdtype: resolved_ipv4
        if rdtype == dns.rdatatype.A
        else resolved_ipv6,
    )

    host = multidyndnscli.Host(
        router,
        testdata_host_config_target_address_from_router['name'],
        testdata_host_config_target_address_from_router['fqdn'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv4'],
        testdata_host_config_target_address_from_router['public_ip_methods']['ipv6'],
    )
    assert host.needs_update() == True


def test_domain_init_from_config(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    datetime_now = datetime.datetime.now()
    updater_mock.get_cache_domain = Mock(
        return_value={multidyndnscli.Domain._key_last_update: datetime_now}
    )
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
    dns_providers = {'test': dns_provider_mock}
    resolved_ipv4, resolved_ipv6 = get_mock_ip_helper(mocker)
    dns_resolver_mock = mocker.patch(
        'dns.resolver.resolve',
        side_effect=lambda fqdn, rdtype: resolved_ipv4
        if rdtype == dns.rdatatype.A
        else resolved_ipv6,
    )
    domain = multidyndnscli.Domain.from_config(
        updater_mock, router_mock, dns_providers, testdata_domain_config
    )
    assert domain._updater == updater_mock
    assert domain._router == router_mock
    assert domain.domain_name == testdata_domain_name
    assert domain._dns_provider == dns_provider_mock
    assert domain._delay == testdata_domain_config['delay']
    assert len(domain._host_list) == 1
    assert domain._host_list[0].fqdn == testdata_domain_config['hosts'][0]['fqdn']
    assert domain._host_list[0].name == testdata_domain_config['hosts'][0]['name']
    assert domain._last_update == datetime_now


def test_domain_init(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    updater_mock.get_cache_domain = Mock(return_value={})
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
    dns_providers = {'test': dns_provider_mock}
    resolved_ipv4, resolved_ipv6 = get_mock_ip_helper(mocker)
    delay = 23
    domain = multidyndnscli.Domain(
        updater_mock, router_mock, testdata_domain_name, dns_provider_mock, delay
    )
    assert domain._updater == updater_mock
    assert domain._router == router_mock
    assert domain.domain_name == testdata_domain_name
    assert domain._dns_provider == dns_provider_mock
    assert domain._delay == delay
    print(domain._host_list)
    assert len(domain._host_list) == 0


def test_domain_add_host(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    updater_mock.get_cache_domain = Mock(return_value={})
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mocker = MagicMock(spec=multidyndnscli.DNSProvider)
    delay = 23
    domain = multidyndnscli.Domain(
        updater_mock, router_mock, testdata_domain_name, dns_provider_mocker, delay
    )
    host_mock = Mock()
    domain.add_host(host_mock)
    assert len(domain._host_list) == 1
    assert domain._host_list[0] == host_mock


def test_domain_update_delay(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    updater_mock.get_cache_domain = Mock(return_value={})
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
    delay = 10000
    datetime_now = datetime.datetime.now()
    updater_mock.get_cache_domain = Mock(
        return_value={multidyndnscli.Domain._key_last_update: datetime_now}
    )
    domain = multidyndnscli.Domain(
        updater_mock, router_mock, testdata_domain_name, dns_provider_mock, delay
    )
    host_mock = Mock()
    host_mock.needs_update = Mock(return_value=True)
    host_mock.fqdn = f'test.{testdata_domain_name}'
    host_mock.host_ipv4 = IPAddress(testdata_ipv4)
    host_mock.get_updated_ipv6_record = Mock(return_value=None)
    domain.add_host(host_mock)
    domain.update()
    dns_provider_mock.update_domain.assert_not_called()


# This methods checks that the list of DNSrecords is equal, including their IDs!


class DNSRecordIdMatcher:
    def __init__(self, expected_records: List[DNSRecord]):
        self.expected_records = expected_records

    def __eq__(self, records: List[DNSRecord]):
        if self.expected_records != records:
            return False
        for my_rec, other_rec in zip(self.expected_records, records):
            if not my_rec.id == other_rec.id:
                return False
        return True


def test_domain_update_ipv4_without_record_id(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    updater_mock.get_cache_domain = Mock(return_value={})
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
    delay = 0
    datetime_now = datetime.datetime.now()
    updater_mock.get_cache_domain = Mock(
        return_value={multidyndnscli.Domain._key_last_update: datetime_now}
    )
    domain = multidyndnscli.Domain(
        updater_mock, router_mock, testdata_domain_name, dns_provider_mock, delay
    )
    host_mock = Mock()
    host_mock.needs_update = Mock(return_value=True)
    host_mock.fqdn = f'test.{testdata_domain_name}'
    host_mock.host_ipv4 = IPAddress(testdata_ipv4)
    host_mock.host_ipv6 = None
    domain.add_host(host_mock)
    domain.update()
    dns_provider_mock.update_domain.assert_called_once_with(
        ANY, testdata_update_record_ipv4
    )


# Check that existing DNS records are found and properly updated using their ID instead of being replaced
def test_domain_update_ipv4_with_record_id(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    updater_mock.get_cache_domain = Mock(return_value={})
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
    dns_provider_mock.fetch_domain = Mock(
        return_value=testdata_update_records_combined_with_ids
    )
    delay = 0
    datetime_now = datetime.datetime.now()
    updater_mock.get_cache_domain = Mock(
        return_value={multidyndnscli.Domain._key_last_update: datetime_now}
    )
    domain = multidyndnscli.Domain(
        updater_mock, router_mock, testdata_domain_name, dns_provider_mock, delay
    )
    host_mock = Mock()
    host_mock.needs_update = Mock(return_value=True)
    host_mock.fqdn = f'test.{testdata_domain_name}'
    host_mock.host_ipv4 = IPAddress(testdata_ipv4)
    host_mock.host_ipv6 = None
    domain.add_host(host_mock)
    domain.update()
    dns_provider_mock.update_domain.assert_called_once_with(
        ANY, DNSRecordIdMatcher(testdata_update_record_ipv4_with_id)
    )


def test_domain_update_ipv6_without_record_id(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    updater_mock.get_cache_domain = Mock(return_value={})
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
    delay = 0
    datetime_now = datetime.datetime.now()
    updater_mock.get_cache_domain = Mock(
        return_value={multidyndnscli.Domain._key_last_update: datetime_now}
    )
    domain = multidyndnscli.Domain(
        updater_mock, router_mock, testdata_domain_name, dns_provider_mock, delay
    )
    host_mock = Mock()
    host_mock.needs_update = Mock(return_value=True)
    host_mock.fqdn = f'test.{testdata_domain_name}'
    host_mock.host_ipv4 = None
    host_mock.host_ipv6 = IPAddress(testdata_ipv6)
    domain.add_host(host_mock)
    domain.update()
    dns_provider_mock.update_domain.assert_called_once_with(
        ANY, testdata_update_record_ipv6
    )


# Check that existing DNS records are found and properly updated using their ID instead of being replaced


def test_domain_update_ipv6_with_record_id(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    updater_mock.get_cache_domain = Mock(return_value={})
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
    dns_provider_mock.fetch_domain = Mock(
        return_value=testdata_update_records_combined_with_ids
    )
    delay = 0
    datetime_now = datetime.datetime.now()
    updater_mock.get_cache_domain = Mock(
        return_value={multidyndnscli.Domain._key_last_update: datetime_now}
    )
    domain = multidyndnscli.Domain(
        updater_mock, router_mock, testdata_domain_name, dns_provider_mock, delay
    )
    host_mock = Mock()
    host_mock.needs_update = Mock(return_value=True)
    host_mock.fqdn = f'test.{testdata_domain_name}'
    host_mock.host_ipv4 = None
    host_mock.host_ipv6 = IPAddress(testdata_ipv6)
    domain.add_host(host_mock)
    domain.update()
    dns_provider_mock.update_domain.assert_called_once_with(
        ANY, DNSRecordIdMatcher(testdata_update_record_ipv6_with_id)
    )


def test_domain_update_ipv4_ipv6_without_ids(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    updater_mock.get_cache_domain = Mock(return_value={})
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
    dns_provider_mock.fetch_domain = Mock(return_value=testdata_update_records_combined)
    delay = 0
    datetime_now = datetime.datetime.now()
    updater_mock.get_cache_domain = Mock(
        return_value={multidyndnscli.Domain._key_last_update: datetime_now}
    )
    domain = multidyndnscli.Domain(
        updater_mock, router_mock, testdata_domain_name, dns_provider_mock, delay
    )
    host_mock = Mock()
    host_mock.needs_update = Mock(return_value=True)
    host_mock.fqdn = f'test.{testdata_domain_name}'
    host_mock.host_ipv4 = IPAddress(testdata_ipv4)
    host_mock.host_ipv6 = IPAddress(testdata_ipv6)
    domain.add_host(host_mock)
    domain.update()
    dns_provider_mock.update_domain.assert_called_once_with(
        ANY, testdata_update_records_combined
    )


# Check that existing DNS records are found and properly updated using their ID instead of being replaced


def test_domain_update_ipv4_ipv6_with_ids(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    updater_mock.get_cache_domain = Mock(return_value={})
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
    dns_provider_mock.fetch_domain = Mock(
        return_value=testdata_update_records_combined_with_ids
    )
    delay = 0
    datetime_now = datetime.datetime.now()
    updater_mock.get_cache_domain = Mock(
        return_value={multidyndnscli.Domain._key_last_update: datetime_now}
    )
    domain = multidyndnscli.Domain(
        updater_mock, router_mock, testdata_domain_name, dns_provider_mock, delay
    )
    host_mock = Mock()
    host_mock.needs_update = Mock(return_value=True)
    host_mock.fqdn = f'test.{testdata_domain_name}'
    host_mock.host_ipv4 = IPAddress(testdata_ipv4)
    host_mock.host_ipv6 = IPAddress(testdata_ipv6)
    domain.add_host(host_mock)
    domain.update()
    dns_provider_mock.update_domain.assert_called_once_with(
        ANY, DNSRecordIdMatcher(testdata_update_records_combined_with_ids)
    )


def test_domain_update_dry_run(mocker):
    updater_mock = MagicMock(spec=multidyndnscli.Updater)
    updater_mock.get_cache_domain = Mock(return_value={})
    router_mock = MagicMock(spec=multidyndnscli.Router)
    dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
    dns_provider_mock.fetch_domain = Mock(
        return_value=testdata_update_records_combined_with_ids
    )
    delay = 0
    datetime_now = datetime.datetime.now()
    updater_mock.get_cache_domain = Mock(
        return_value={multidyndnscli.Domain._key_last_update: datetime_now}
    )
    domain = multidyndnscli.Domain(
        updater_mock, router_mock, testdata_domain_name, dns_provider_mock, delay
    )
    host_mock = Mock()
    host_mock.needs_update = Mock(return_value=True)
    host_mock.fqdn = f'test.{testdata_domain_name}'
    host_mock.host_ipv4 = IPAddress(testdata_ipv4)
    host_mock.host_ipv6 = IPAddress(testdata_ipv6)
    domain.add_host(host_mock)
    domain.update(dry_run=True)
    dns_provider_mock.update_domain.assert_not_called()


def test_router_init_called_from_config(mocker):
    init_mock = Mock(return_value=None)
    mocker.patch.object(multidyndnscli.Router, '__init__', init_mock)
    router = multidyndnscli.Router.from_config(testdata_router_method_web)
    init_mock.assert_called_once_with(
        testdata_router_method_web['ipv4'], testdata_router_method_web['ipv6']
    )


def test_router_init_neither_ipv4_nor_ipv6(mocker):
    router = multidyndnscli.Router(None, None)
    assert router.ipv4 == None
    assert router.ipv6 == None
    assert not router.use_ipv4
    assert not router.use_ipv6


def test_router_init_ipv4_exception(mocker):
    mocker.patch('requests.get', return_value=None)
    with pytest.raises(Exception):
        router = multidyndnscli.Router(testdata_router_method_web['ipv4'], None)


def test_router_init_ipv6_exception(mocker):
    mocker.patch('requests.get', return_value=None)
    with pytest.raises(Exception):
        router = multidyndnscli.Router(None, testdata_router_method_web['ipv6'])


def test_router_init_ipv4_web_invalid_exception(mocker):
    requests_response = Mock()
    requests_response.text = 'invalid-ip-address'
    mocker.patch('requests.get', return_value=requests_response)
    with pytest.raises(Exception):
        router = multidyndnscli.Router(testdata_router_method_web['ipv4'], None)


def test_router_init_ipv6_web_invalid_exception(mocker):
    requests_response = Mock()
    requests_response.text = 'invalid-ip-address'
    mocker.patch('requests.get', return_value=requests_response)
    with pytest.raises(Exception):
        router = multidyndnscli.Router(None, testdata_router_method_web['ipv6'])


def test_router_init_ipv4_web(mocker):
    requests_response = Mock()
    requests_response.text = testdata_ipv4
    mocker.patch('requests.get', return_value=requests_response)
    router = multidyndnscli.Router(testdata_router_method_web['ipv4'], None)
    assert router.ipv4 == IPAddress(testdata_ipv4)
    assert router.ipv6 == None
    assert router.use_ipv4
    assert not router.use_ipv6


def test_router_init_ipv6_web(mocker):
    requests_response = Mock()
    requests_response.text = testdata_ipv6
    mocker.patch('requests.get', return_value=requests_response)
    router = multidyndnscli.Router(None, testdata_router_method_web['ipv6'])
    assert router.ipv4 == None
    assert router.ipv6 == IPAddress(testdata_ipv6)
    assert not router.use_ipv4
    assert router.use_ipv6


def test_router_init_both_web(mocker):
    called_once = False
    requests_response_ipv4 = Mock()
    requests_response_ipv4.text = testdata_ipv4
    requests_response_ipv6 = Mock()
    requests_response_ipv6.text = testdata_ipv6
    # Return IPv4 on first call, IPv6 on second
    mocker.patch(
        'requests.get', side_effect=[requests_response_ipv4, requests_response_ipv6]
    )
    router = multidyndnscli.Router(
        testdata_router_method_web['ipv4'], testdata_router_method_web['ipv6']
    )
    assert router.ipv4 == IPAddress(testdata_ipv4)
    assert router.ipv6 == IPAddress(testdata_ipv6)
    assert router.use_ipv4
    assert router.use_ipv6


def test_router_init_ipv4_wan_no_ip(mocker):
    mocker.patch('multidyndnscli.util.get_ipv4_addresses_linux', return_value=[])
    router = multidyndnscli.Router(testdata_router_method_wan['ipv4'], None)
    assert router.ipv4 == None
    assert router.ipv6 == None


def test_router_init_ipv4_wan(mocker):
    mocker.patch(
        'multidyndnscli.util.get_ipv4_addresses_linux',
        return_value=[IPAddress(testdata_ipv4)],
    )
    router = multidyndnscli.Router(testdata_router_method_wan['ipv4'], None)
    assert router.ipv4 == IPAddress(testdata_ipv4)
    assert router.ipv6 == None


def test_router_init_ipv6_wan_no_ip(mocker):
    mocker.patch('multidyndnscli.util.get_ipv6_addresses_linux', return_value=[])
    router = multidyndnscli.Router(None, testdata_router_method_wan['ipv6'])
    assert router.ipv4 == None
    assert router.ipv6 == None


def test_router_init_ipv6_wan(mocker):
    mocker.patch(
        'multidyndnscli.util.get_ipv6_addresses_linux',
        return_value=[IPAddress(testdata_ipv6)],
    )
    router = multidyndnscli.Router(None, testdata_router_method_wan['ipv6'])
    assert router.ipv4 == None
    assert router.ipv6 == IPAddress(testdata_ipv6)


class FritzStatusMock:
    def __init__(self, ipv4=None, ipv6=None):
        self._ipv4 = ipv4
        self._ipv6 = ipv6

    @property
    def external_ip(self):
        return self._ipv4

    @property
    def external_ipv6(self):
        return self._ipv6


def test_router_init_ipv4_fritzbox(mocker):
    with mocker.patch('fritzconnection.FritzConnection', return_value=Mock()):
        with mocker.patch(
            'fritzconnection.lib.fritzstatus.FritzStatus',
            return_value=FritzStatusMock(ipv4=testdata_ipv4),
        ) as status_mock:
            router = multidyndnscli.Router(
                testdata_router_method_fritz_box['ipv4'], None
            )
            assert router.ipv4 == IPAddress(testdata_ipv4)
            assert router.ipv6 == None


def test_router_init_ipv6_fritzbox(mocker):
    with mocker.patch('fritzconnection.FritzConnection', return_value=Mock()):
        with mocker.patch(
            'fritzconnection.lib.fritzstatus.FritzStatus',
            return_value=FritzStatusMock(ipv6=testdata_ipv6),
        ) as status_mock:
            router = multidyndnscli.Router(
                None, testdata_router_method_fritz_box['ipv6']
            )
            assert router.ipv4 == None
            assert router.ipv6 == IPAddress(testdata_ipv6)


def test_router_init_ips_both_fritzbox(mocker):
    with mocker.patch('fritzconnection.FritzConnection', return_value=Mock()):
        with mocker.patch(
            'fritzconnection.lib.fritzstatus.FritzStatus',
            return_value=FritzStatusMock(ipv4=testdata_ipv4, ipv6=testdata_ipv6),
        ):
            router = multidyndnscli.Router(
                testdata_router_method_fritz_box['ipv4'],
                testdata_router_method_fritz_box['ipv6'],
            )
            assert router.ipv4 == IPAddress(testdata_ipv4)
            assert router.ipv6 == IPAddress(testdata_ipv6)


def test_router_init_ipv4_fritzbox_exception(mocker):
    with mocker.patch(
        'fritzconnection.FritzConnection',
        side_effect=fritzconnection.core.exceptions.FritzConnectionException(),
    ):
        with pytest.raises(Exception):
            router = multidyndnscli.Router(
                testdata_router_method_fritz_box['ipv4'], None
            )


def test_router_init_ipv6_fritzbox_exception(mocker):
    with mocker.patch(
        'fritzconnection.FritzConnection',
        side_effect=fritzconnection.core.exceptions.FritzConnectionException(),
    ):
        with pytest.raises(Exception):
            router = multidyndnscli.Router(
                None, testdata_router_method_fritz_box['ipv6']
            )


def test_router_init_ipv4_illegal_method_exception(mocker):
    with pytest.raises(Exception):
        router = multidyndnscli.Router(testdata_router_method_illegal['ipv4'], None)


def test_router_init_ipv6_illegal_method__exception(mocker):
    with pytest.raises(Exception):
        router = multidyndnscli.Router(None, testdata_router_method_illegal['ipv6'])


def test_dnsprovider_netcup_from_config():
    netcup = multidyndnscli.Netcup.from_config(testdata_dnsprovider_netcup)
    assert netcup._userid == int(testdata_dnsprovider_netcup['userid'])
    assert netcup._apikey == testdata_dnsprovider_netcup['apikey']
    assert netcup._apipass == testdata_dnsprovider_netcup['apipass']


def test_dnsprovider_netcup_constructor():
    netcup = multidyndnscli.Netcup(
        int(testdata_dnsprovider_netcup['userid']),
        testdata_dnsprovider_netcup['apikey'],
        testdata_dnsprovider_netcup['apipass'],
    )
    assert netcup._userid == int(testdata_dnsprovider_netcup['userid'])
    assert netcup._apikey == testdata_dnsprovider_netcup['apikey']
    assert netcup._apipass == testdata_dnsprovider_netcup['apipass']


def test_dnsprovider_netcup_fetch(mocker):
    client_mock = MagicMock(spec=Client)
    client_mock.return_value.dns_records.return_value = Mock(
        return_value=['test.domain.invalid']
    )
    mocker.patch('multidyndnscli.Client', client_mock)
    netcup = multidyndnscli.Netcup(
        int(testdata_dnsprovider_netcup['userid']),
        testdata_dnsprovider_netcup['apikey'],
        testdata_dnsprovider_netcup['apipass'],
    )
    domain = Mock()
    domain.domain_name = 'test.invalid'
    domains = netcup.fetch_domain(domain)
    client_mock.assert_called_once_with(
        int(testdata_dnsprovider_netcup['userid']),
        testdata_dnsprovider_netcup['apikey'],
        testdata_dnsprovider_netcup['apipass'],
    )
    client_mock.return_value.dns_records.return_value.called_once_with(
        domain.domain_name
    )


def test_dnsprovider_netcup_update(mocker):
    client_mock = MagicMock(spec=Client)
    client_mock.return_value.update_dns_records.return_value = Mock()
    mocker.patch('multidyndnscli.Client', client_mock)
    netcup = multidyndnscli.Netcup(
        int(testdata_dnsprovider_netcup['userid']),
        testdata_dnsprovider_netcup['apikey'],
        testdata_dnsprovider_netcup['apipass'],
    )
    domain = Mock()
    domain.domain_name = 'test.invalid'
    domains = netcup.update_domain(domain, testdata_update_records_combined_with_ids)
    client_mock.assert_called_once_with(
        int(testdata_dnsprovider_netcup['userid']),
        testdata_dnsprovider_netcup['apikey'],
        testdata_dnsprovider_netcup['apipass'],
    )
    client_mock.return_value.update_dns_records.return_value.called_once_with(
        domain.domain_name, testdata_update_records_combined_with_ids
    )

def test_updater_constructor():
    # Without cache dir
    updater = multidyndnscli.Updater(None)
    assert updater.cache_dir == None
    # With cache dir
    path = Path('test')
    updater = multidyndnscli.Updater(path)
    assert updater.cache_dir == path
    assert updater.dns_providers == {}
    assert updater.domains == []

def test_updater_from_config_router_not_reachable_exception(mocker):
    # Mock Netcup DNS provider
    netcup_mock = MagicMock(spec=multidyndnscli.Netcup)
    netcup_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Netcup', netcup_mock)
    # Mock Router
    router_mock = Mock()
    router_mock.from_config = Mock(side_effect=multidyndnscli.RouterNotReachableException())
    mocker.patch('multidyndnscli.Router', router_mock)
    # Mock Domain
    domain_mock = MagicMock(spec=multidyndnscli.Domain)
    domain_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Domain', domain_mock)
    with pytest.raises(Exception):
        updater = multidyndnscli.Updater.from_config(testdata_updater_config_mock)

def test_updater_from_config_without_cache_file(mocker):
    # Mock Netcup DNS provider
    netcup_mock = MagicMock(spec=multidyndnscli.Netcup)
    netcup_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Netcup', netcup_mock)
    # Mock Router
    router_mock = MagicMock(spec=multidyndnscli.Router)
    router_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Router', router_mock)
    # Mock Domain
    domain_mock = MagicMock(spec=multidyndnscli.Domain)
    domain_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Domain', domain_mock)
    updater = multidyndnscli.Updater.from_config(testdata_updater_config_mock)
    assert updater.dns_providers == { testdata_updater_config_mock['dns-providers'][0]['name']: netcup_mock.from_config.return_value}
    netcup_mock.from_config.assert_called_once_with(testdata_updater_config_mock['dns-providers'][0])
    router_mock.from_config.assert_called_once_with(testdata_updater_config_mock['router'])
    domain_mock.from_config.assert_called_once_with(updater,
                                                    router_mock.from_config.return_value,
                                                    { testdata_updater_config_mock['dns-providers'][0]['name']: netcup_mock.from_config.return_value},
                                                    testdata_updater_config_mock['domains'][0])

def test_updater_from_config_with_cache_dir_without_cache_file(mocker, tmp_path):
    # Mock Netcup DNS provider
    netcup_mock = MagicMock(spec=multidyndnscli.Netcup)
    netcup_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Netcup', netcup_mock)
    # Mock Router
    router_mock = MagicMock(spec=multidyndnscli.Router)
    router_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Router', router_mock)
    # Mock Domain
    domain_mock = MagicMock(spec=multidyndnscli.Domain)
    domain_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Domain', domain_mock)
    testdata_updater_config_mock_with_cache_dir = testdata_updater_config_mock.copy()
    testdata_updater_config_mock_with_cache_dir['common']['cache_dir'] = str(tmp_path)
    updater = multidyndnscli.Updater.from_config(testdata_updater_config_mock_with_cache_dir)
    assert updater.cache_dir == tmp_path
    assert updater.dns_providers == { testdata_updater_config_mock_with_cache_dir['dns-providers'][0]['name']: netcup_mock.from_config.return_value}
    netcup_mock.from_config.assert_called_once_with(testdata_updater_config_mock_with_cache_dir['dns-providers'][0])
    router_mock.from_config.assert_called_once_with(testdata_updater_config_mock_with_cache_dir['router'])
    domain_mock.from_config.assert_called_once_with(updater,
                                                    router_mock.from_config.return_value,
                                                    { testdata_updater_config_mock_with_cache_dir['dns-providers'][0]['name']: netcup_mock.from_config.return_value},
                                                    testdata_updater_config_mock_with_cache_dir['domains'][0])
    assert updater._cache == {}

def test_updater_from_config_with_cache_dir_with_cache_file(mocker, tmp_path):
    cache_file = tmp_path / Path(multidyndnscli.CACHE_FILE_NAME)
    test_cache_content = {'domain.invalid': { 'key': 'value' } }
    with open(cache_file, 'w') as f:
        yaml.dump(test_cache_content, f)
    # Mock Netcup DNS provider
    netcup_mock = MagicMock(spec=multidyndnscli.Netcup)
    netcup_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Netcup', netcup_mock)
    # Mock Router
    router_mock = MagicMock(spec=multidyndnscli.Router)
    router_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Router', router_mock)
    # Mock Domain
    domain_mock = MagicMock(spec=multidyndnscli.Domain)
    domain_mock.from_config = Mock()
    mocker.patch('multidyndnscli.Domain', domain_mock)
    testdata_updater_config_mock_with_cache_dir = testdata_updater_config_mock.copy()
    testdata_updater_config_mock_with_cache_dir['common']['cache_dir'] = str(tmp_path)
    updater = multidyndnscli.Updater.from_config(testdata_updater_config_mock_with_cache_dir)
    assert updater.cache_dir == tmp_path
    assert updater.dns_providers == { testdata_updater_config_mock_with_cache_dir['dns-providers'][0]['name']: netcup_mock.from_config.return_value}
    netcup_mock.from_config.assert_called_once_with(testdata_updater_config_mock_with_cache_dir['dns-providers'][0])
    router_mock.from_config.assert_called_once_with(testdata_updater_config_mock_with_cache_dir['router'])
    domain_mock.from_config.assert_called_once_with(updater,
                                                    router_mock.from_config.return_value,
                                                    { testdata_updater_config_mock_with_cache_dir['dns-providers'][0]['name']: netcup_mock.from_config.return_value},
                                                    testdata_updater_config_mock_with_cache_dir['domains'][0])
    assert updater._cache == test_cache_content

def test_updater_write_read_cache(mocker, tmp_path):
    cache_file = tmp_path / Path(multidyndnscli.CACHE_FILE_NAME)
    test_cache_content = {testdata_domain_name: { 'key': 'value' } }
    with open(cache_file, 'w') as f:
        yaml.dump(test_cache_content, f)
    updater = multidyndnscli.Updater(tmp_path)
    assert updater.cache_dir == tmp_path
    updater.read_cache()
    assert updater._cache == test_cache_content
    assert updater.get_cache_domain(testdata_domain_name) == test_cache_content[testdata_domain_name]
    assert updater.get_cache_domain(testdata_domain_name_other) == {}
    # Change something
    test_cache_content[testdata_domain_name] = { 'key': 'new_value'}
    test_cache_content[testdata_domain_name_other] = { 'key': 'other'}
    updater.update_cache_domain(testdata_domain_name, test_cache_content[testdata_domain_name])
    updater.update_cache_domain(testdata_domain_name_other, test_cache_content[testdata_domain_name_other])
    assert updater.get_cache_domain(testdata_domain_name) == test_cache_content[testdata_domain_name]
    assert updater.get_cache_domain(testdata_domain_name_other) == test_cache_content[testdata_domain_name_other]
    updater.write_cache()
    with open(cache_file, 'r') as f:
        test_cache_content_from_file = yaml.safe_load(f)
    assert updater._cache == test_cache_content_from_file


def test_updater_handle_empty_cache_file(mocker, tmp_path):
    cache_file = tmp_path / Path(multidyndnscli.CACHE_FILE_NAME)
    test_cache_content = ''
    with open(cache_file, 'w') as f:
        yaml.dump(test_cache_content, f)
    updater = multidyndnscli.Updater(tmp_path)
    assert updater.cache_dir == tmp_path
    updater.read_cache()
    assert updater._cache == {}

def test_updater_set_get_cache_dir(tmp_path):
    updater = multidyndnscli.Updater(None)
    assert updater.cache_dir == None
    updater.cache_dir = tmp_path
    assert updater.cache_dir == tmp_path

def test_updater_update_dry_run(mocker):
    # Mock Domain
    domain_mock = MagicMock(spec=multidyndnscli.Domain)
    domain_mock_other = MagicMock(spec=multidyndnscli.Domain)
    updater = multidyndnscli.Updater()
    updater.add_domain(domain_mock)
    updater.add_domain(domain_mock_other)
    updater.update(True)
    domain_mock.update.assert_called_once_with(True)
    domain_mock_other.update.assert_called_once_with(True)

def test_updater_update_no_dry_run(mocker):
    # Mock Domain
    domain_mock = MagicMock(spec=multidyndnscli.Domain)
    domain_mock_other = MagicMock(spec=multidyndnscli.Domain)
    updater = multidyndnscli.Updater()
    updater.add_domain(domain_mock)
    updater.add_domain(domain_mock_other)
    updater.update(False)
    domain_mock.update.assert_called_once_with(False)
    domain_mock_other.update.assert_called_once_with(False)

import datetime
from typing import List
from unittest.mock import MagicMock, Mock, ANY
import dns
from netaddr import IPAddress
import pytest
import multidyndnscli
from nc_dnsapi import DNSRecord

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
    DNSRecord(
        hostname='test', type='A', destination=testdata_ipv4
    )]

testdata_update_record_ipv4_with_id = [
    DNSRecord(
        hostname='test', type='A', destination=testdata_ipv4, id=23
    )]

testdata_update_record_ipv6 = [
    DNSRecord(
        hostname='test', type='AAAA', destination=testdata_ipv6
    )]

testdata_update_record_ipv6_with_id = [
    DNSRecord(
        hostname='test', type='AAAA', destination=testdata_ipv6, id=42
    )]
testdata_update_records_combined = testdata_update_record_ipv4 + \
  testdata_update_record_ipv6
testdata_update_records_combined_with_ids = testdata_update_record_ipv4_with_id + \
  testdata_update_record_ipv6_with_id


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
    ANY, testdata_update_record_ipv4)


# Check that existing DNS records are found and properly updated using their ID instead of being replaced
def test_domain_update_ipv4_with_record_id(mocker):
  updater_mock = MagicMock(spec=multidyndnscli.Updater)
  updater_mock.get_cache_domain = Mock(return_value={})
  router_mock = MagicMock(spec=multidyndnscli.Router)
  dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
  dns_provider_mock.fetch_domain = Mock(
    return_value=testdata_update_records_combined_with_ids)
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
    ANY, DNSRecordIdMatcher(testdata_update_record_ipv4_with_id))


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
    ANY, testdata_update_record_ipv6)

# Check that existing DNS records are found and properly updated using their ID instead of being replaced
def test_domain_update_ipv6_with_record_id(mocker):
  updater_mock = MagicMock(spec=multidyndnscli.Updater)
  updater_mock.get_cache_domain = Mock(return_value={})
  router_mock = MagicMock(spec=multidyndnscli.Router)
  dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
  dns_provider_mock.fetch_domain = Mock(
    return_value=testdata_update_records_combined_with_ids)
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
    ANY, DNSRecordIdMatcher(testdata_update_record_ipv6_with_id))


def test_domain_update_ipv4_ipv6_without_ids(mocker):
  updater_mock = MagicMock(spec=multidyndnscli.Updater)
  updater_mock.get_cache_domain = Mock(return_value={})
  router_mock = MagicMock(spec=multidyndnscli.Router)
  dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
  dns_provider_mock.fetch_domain = Mock(
    return_value=testdata_update_records_combined)
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
    ANY, testdata_update_records_combined)

# Check that existing DNS records are found and properly updated using their ID instead of being replaced
def test_domain_update_ipv4_ipv6_with_ids(mocker):
  updater_mock = MagicMock(spec=multidyndnscli.Updater)
  updater_mock.get_cache_domain = Mock(return_value={})
  router_mock = MagicMock(spec=multidyndnscli.Router)
  dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
  dns_provider_mock.fetch_domain = Mock(
    return_value=testdata_update_records_combined_with_ids)
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
    ANY, DNSRecordIdMatcher(testdata_update_records_combined_with_ids))

def test_domain_update_dry_run(mocker):
  updater_mock = MagicMock(spec=multidyndnscli.Updater)
  updater_mock.get_cache_domain = Mock(return_value={})
  router_mock = MagicMock(spec=multidyndnscli.Router)
  dns_provider_mock = MagicMock(spec=multidyndnscli.DNSProvider)
  dns_provider_mock.fetch_domain = Mock(
    return_value=testdata_update_records_combined_with_ids)
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

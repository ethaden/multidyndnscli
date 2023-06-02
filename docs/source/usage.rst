Usage
=====

Configuration
~~~~~~~~~~~~~

A full config file example is shown below:

.. code-block:: yaml

    common:
      # Cache dir for storing data
      cache_dir: "<existing writable folder for caching data>"
    dns_providers:
    # List of DNS providers, each having a unique name used below under "domains"
        # A unique name for this DNS provider entry
      - name: "Netcup"
        # Type of DNS provider. Currently, only "Netcup" is supported
        type: "Netcup"
        # The Netcup User ID
        userid: "<netcup-userid>"
        # The Netcup API key
        apikey: "<netcup-apikey>"
        # The Netcup API password
        apipass: "<netcup-apipass>"
    router:
      ipv4:
        enabled: true
        # method to resolve public IPv4: "web", "wan" or "fritzbox"
        #method: "web"
        # If method is "web": address of server to query IPv4 from
        #web_url: "http://myexternalip.com/raw"
        # If method is "web": an optional timeout
        #web_timeout: 60
        method: "wan"
        # If method is "wan": Name of the local WAN network interface
        wan_interface: "<put-wan-iface-here>"
        #method: "fritzbox"
        # If method is "fritzbox": IP of Fritz!Box
        #fritzbox_address: "<fritz-box-ip-address>"
        # If method is "fritzbox": Wether or not to use TLS
        #fritzbox_tls: false
      ipv6:
        enabled: true
        # method to resolve public IPv6: "web", "wan" or "fritzbox"
        #method: "web"
        # If method is "web": address of server to query IPv6 from
        #web_url: "http://myexternalip.com/raw"
        # If method is "web": an optional timeout
        #web_timeout: 60
        method: "wan"
        # If method is "wan": Name of the local WAN network interface
        wan_interface: "<put-wan-iface-here>"
        #method: "fritzbox"
        # If method is "fritzbox": IP of Fritz!Box
        #fritzbox_address: "<fritz-box-ip-address>"
        # If method is "fritzbox": Wether or not to use TLS
        #fritzbox_tls: false
    domains:
      - name: "test.invalid"
        # Name of the dns provider to be used as onfigured above
        dns_provider: "Netcup"
        # The minimal delay in seconds to wait until next updated. Increase if using dnssec (as resigning the updated records takes quite a lot time)
        delay: 300
        # List of hosts
        hosts:
            # the internal fully qualified domain name
          - name: "openwrt.lan"
            # The public fully qualified domain name
            fqdn: "openwrt.home.test.invalid"
            # method for resolving the desired IP address
            public_ip_methods:
              # the method for IPv4: "router" or "local_dns"
              ipv4: "router"
              # the method for IPv6: "router" or "local_dns"
              ipv6: "router"
            # the internal fully qualified domain name
          - name: "server.lan"
            # The public fully qualified domain name
            fqdn: "server.home.test.invalid"
            # method for resolving the desired IP address
            public_ip_methods:
              # the method for IPv4: "router" or "local_dns"
              ipv4: "router"
              # the method for IPv6: "router" or "local_dns"
              ipv6: "local_dns"

Explanation of Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^

Section ``common``
""""""""""""""""""

``cache_dir``: A folder where a cache file is stored. Must be writable by user running the tool.

Section ``dns_providers``
"""""""""""""""""""""""""

This section can contain multiple DNS providers. At least one provider must be specified.

``name``: Name of the configuration entry. Domain entries can refer to specific DNS provider using its configuration name

``type``: Type of the DNS provider. Currently, only ``Netcup`` is supported.


For DNS provider ``Netcup``:

``userid``: The Netcup User ID (customer ID)

``apikey``: The Netcup API Key

``apipass``: The Netcup API Password


Section ``router``
""""""""""""""""""

This section specifies the router configuration. We assume, that there is exactly on router

``ipv4``: Settings for IPv4

``method``: The method how to find the public IPv4 of the router. 
Can be either ``web`` where an external HTTP service is queried for the raw IP address. 
Or ``wan``, where the first public IPv4 is taken from the WAN interface specified in ``wan_interface``.
Finally, the value ``fritzbox`` specifies that a locally running Fritz!Box is queried via ``fritzbox_address``.
TLS is used if ``fritzbox_tls`` is ``true``.


``ipv6``: Settings for IPv6

``method``: The method how to find the public IPv6 of the router. 
Can be either ``web`` where an external HTTP service is queried for the raw IP address. 
Or ``wan``, where the first public IPv6 is taken from the WAN interface specified in ``wan_interface``.
Finally, the value ``fritzbox`` specifies that a locally running Fritz!Box is queried via ``fritzbox_address``.
TLS is used if ``fritzbox_tls`` is ``true``.

Section ``domains``
"""""""""""""""""""

A list of domains to use. Each list entry consists of the following properties.

``name``: Public fully qualified domain name of the domain to handle.

``dns_provider``: Specify the name of the above configured DNS providers to use to handle this domain.

``hosts``: A list of hosts on the intranet to handle. Each list entry consists of the following properties.

List of hosts, each with the following properties:

``name``: The internal fully qualified domain name used to query the local DNS resolver for the current IP of the host

``fqdn``: Fully qualified domain name of the host. Must be a sub record of the domain name

``public_ip_methods``: Specifies the public IP addresses to which the public FQDN of this host shall point to.

``ipv4``: If ``router``, the public IPv4 or the router is used. If ``local_dns``, the first public IPv4 resolved for the internal host is used.

``ipv6``: If ``router``, the public IPv6 or the router is used. If ``local_dns``, the first public IPv6 resolved for the internal host is used.


Running the Tool periodically
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use a cronjob or systemd to run the tool periodically.
It is highly recommended not to run the tool with root privileges.

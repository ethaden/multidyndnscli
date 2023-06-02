# DynDNS Command Line Tool [![Test](https://github.com/ethaden/multidyndnscli/actions/workflows/test.yml/badge.svg)](https://github.com/ethaden/multidyndnscli/actions/workflows/test.yml) 

## Installation
Install the package from Pypi (https://pypi.org/project/multidyndnscli) by running `pip install multidyndnscli`. It requires Python 3.8+.

## Installation on OpenWRT
First, install the required packages on OpenWRT:

```bash
opkg install python3 python3-yaml python3-dns python3-netaddr python3-netifaces
```

Then install the Pypi packages as described above.

## Usage

Create a config file and customize it. An example might look like this:

```
common:
  cache_dir: "<existing writable folder for caching data>"
dns_providers:
  - name: "Netcup"
    type: "Netcup"
    userid: "<netcup-userid>"
    apikey: "<netcup-apikey>"
    apipass: "<netcup-apipass>"
router:
  ipv4:
    method: "wan"
    wan_interface: "<put-wan-iface-here>"
  ipv6:
    enabled: true
    method: "wan"
    wan_interface: "<put-wan-iface-here>"
domains:
  - name: "test.invalid"
    # Name of the dns provider to be used. Configured above
    dns_provider: "Netcup"
    # The minimal delay in seconds to wait until next updated. Increase if using dnssec (as resigning the updated records takes quite a lot time)
    delay: 300
    # List of hosts
    hosts:
      - name: "openwrt.lan"
        fqdn: "openwrt.home.test.invalid"
        public_ip_methods:
          ipv4: "router"
          ipv6: "router"
      - name: "server.lan"
        fqdn: "server.home.test.invalid"
        public_ip_methods:
          ipv4: "router"
          ipv6: "local_dns"
```

Create a folder for caching data which is writable by the user who runs the script and specify its location in `cache_dir`.

Configure your DNS provider. Note, that currently only Netcup is supported.

In our example, the script is running directly on the router. The router's IP addresses are identified by getting the public addresses of the specified WAN interface. Below, one domain called `test.invalid` is configured which consists of two local hosts. The `name` has to be equal to the fully-qualified domain name used internally to talk the respective hosts. The `fqdn` is the public DNS name which should point to the IP addresses of that host or the router. In many cases, there is only one public IPv4 address for the router and all internal hosts use private IPv4 addresses. In such a case, using `ipv4: "router"` in `public_ip_methods` will use the router's IPv4 address for the public FQDN. For IPv6, usually each host as well as the router will have public IPv6 addresses. Using `ipv6: "local_dns"` will make sure that the local DNS server is queried for each host's name and the first public IPv6 found is used for reconfiguring the public DNS.

For every configured domain, all records to be updated will be identified and the whole domain will be changed using only one query to the DNS providers API. In the example, a `delay` of 300 seconds has been configured. If the last update for the domain has been done less tehn `delay` seconds ago, the current update will be skipped. This is particularly useful for DNSSEC-enabled domains, where the domain has to be resigned after any updates. Resigning may take quite a while and no further updates should be done until the updated values have become visible.

For further information, have a look at the documentation: https://ethaden.github.io/multidyndnscli/.

## Development

### Using a dev container
If using Visual Studio Code, you'll can make use of a working dev container setup specified in `.vscode` which should be found automatically. Make sure to adapt the WAN interface used for testing - if any - to the one configure within the running container.

### Local development `pyenv`
This project can use `pyenv`, though using it is not mandatory. You can install `pyenv` by following the instructions on the pyenv website https://github.com/pyenv/pyenv.

List installable versions
```
pyenv install -l
```

Initialize the required/desired python environments:
```
pyenv install 3.8
pyenv install 3.9
pyenv install 3.10
pyenv install 3.11
```

Show installed version:
```
pyenv versions
```

#### Installing `poetry`
This project use based on `poetry`. You can install `poetry` by following the instructions on the poetry website https://python-poetry.org/.

#### Install all packages with poetry

For development including tools for generating documentation, use:

```
poetry install -E docs
```

For installing only the packages required to run the tool, use:

```
poetry install --without dev
```

#### Installing pre-commit
Run the following to enable python pre-commit:
```
poetry run pre-commit install
```

You can run the pre-commit scripts manually:
```
poetry run pre-commit run --all-files
```

### Running tests
You can use `tox`:
```
tox
```

Alternatively, you can run `pytest` manually:
```
poetry run pytest
```

### Running code formatter

```
poetry run black --skip-string-normalization .
```

Alternatively, run formatter with tox:

```
tox -e format
```

### Run linter
```
poetry run pylint multidyndnscli
```

Alternatively, run linter with tox:

```
tox -e linter
```


### Running code analysis with mypy
```
poetry run mypy multidyndnscli
```

### Run coverage analysis
```
poetry run coverage run -m pytest --cov#multidyndnscli && poetry run coverage report -m
```

### Build the docs
First, install the extra packages for building the docs:
```
poetry install --extras docs
```

Build the docs in folder `docs`:

```
poetry run pdoc -o docs multidyndnscli
```

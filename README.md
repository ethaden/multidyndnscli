# DynDNS Command Line Tool

## Installation
```bash
pip install multidyndnscli
```

## Installation on OpenWRT
First, install the required packages on OpenWRT:

```bash
opkg install python3 python3-yaml python3-dns python3-netaddr python3-netifaces
```

## Usage
TODO

## Development

### Installing `pyenv`
This project uses `pyenv`. You can install `pyenv` by following the instructions on the pyenv website https://github.com/pyenv/pyenv.

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

### Installing `poetry`
This project use based on `poetry`. You can install `poetry` by following the instructions on the poetry website https://python-poetry.org/.

### Installing pre-commit
Run the following to enable python pre-commit:
```
poetry run pre-commit install
```

You can run the pre-commit scripts manually:
```
poetry run pre-commit run --all-files
```

### Running tests
You can run `tox`:
```
tox
```

Alternatively, you can run `pytest` manually:
```
poetry run pytest
```

### Running code formatter
```
poetry run black .
```
### Run linter
```
poetry run pylint multidyndnscli
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

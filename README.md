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

### Install all packages with poetry

For development including tools for generating documentation, use:

```
poetry install -E docs
```

For installing only the packages required to run the tool, use:

```
poetry install --without dev
```

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
poetry run coverage run -m pytest --cov=multidyndnscli && poetry run coverage report -m
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

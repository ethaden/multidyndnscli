FROM mcr.microsoft.com/devcontainers/python:3
ARG PYTHON_PACKAGES="python3.8 python3.9 python3.10 python3 python3-pip python3-venv"
ARG DEBIAN_FRONTEND=noninteractive
ENV GPG_TTY /dev/console
RUN apt-get update && apt-get install --no-install-recommends -yq software-properties-common gpg-agent git git-extras vim \
     && add-apt-repository ppa:deadsnakes/ppa && apt-get update \
     && apt-get install -yq --no-install-recommends ${PYTHON_PACKAGES} \
     && pip3 install --no-cache-dir --upgrade pip setuptools wheel

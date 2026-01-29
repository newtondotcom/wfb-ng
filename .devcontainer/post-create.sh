#!/bin/bash
set -e

echo "Installing wfb-ng development dependencies..."

# Update system packages
apt-get update
apt-get install -y --no-install-recommends \
  build-essential \
  pkg-config \
  libsodium-dev \
  libpcap-dev \
  socat \
  iw \
  git \
  virtualenv

# Install Python development packages
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install twisted pyroute2 pyserial msgpack jinja2 pyyaml

# Build the project
echo "Building wfb-ng..."
make clean
make all_bin

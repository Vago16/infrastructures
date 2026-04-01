#!/bin/bash
set -e

echo "🔹 Updating package lists..."
sudo apt update

echo "🔹 Installing required packages..."
sudo apt install -y \
  build-essential \
  libssl-dev \
  libgmp-dev \
  libzmq3-dev \
  astyle \
  cmake \
  gcc \
  ninja-build \
  python3-pytest \
  python3-pytest-xdist \
  unzip \
  xsltproc \
  doxygen \
  graphviz \
  python3-yaml \
  valgrind

echo "🔹 Cloning liboqs..."
if [ ! -d "liboqs" ]; then
  git clone -b main https://github.com/open-quantum-safe/liboqs.git
fi

cd liboqs

# Remove existing build folder if it exists
if [ -d "build" ]; then
    echo "🔹 Removing existing build folder..."
    rm -rf build
fi

# Create fresh build folder
mkdir build && cd build

echo "🔹 Building liboqs..."
cmake -GNinja ..
ninja

echo "🔹 Installing liboqs..."
sudo ninja install
sudo ldconfig

echo "✅ All dependencies installed successfully!"

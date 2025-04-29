#!/bin/bash

echo "============================="
echo "Setting up Blockchain Node..."
echo "============================="

# System Parameters for IoT vs. Full Nodes
export NODE_TYPE="BLOCKCHAIN"
export MAX_MEMORY_MB=1024  # Default memory for full nodes
export LOW_POWER_MODE=false

# Detect IoT Device Based on Hardware Specs
RAM_SIZE_MB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
if [ "$RAM_SIZE_MB" -lt 512000 ]; then  # If less than 512MB RAM, classify as IoT
    export NODE_TYPE="IOT"
    export MAX_MEMORY_MB=256
    export LOW_POWER_MODE=true
    echo "IoT Device Detected - Applying IoT Optimizations..."
else
    echo "Full Blockchain Node Detected - Setting up Full Configuration..."
fi

# Install Core Dependencies
echo "Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

echo "Installing Python and required libraries..."
sudo apt-get install -y python3 python3-pip python3-venv

# Set up Virtual Environment
echo "Creating a Python virtual environment..."
python3 -m venv zk-sse-env
source zk-sse-env/bin/activate

# Install Required Python Packages
echo "Installing cryptographic and blockchain dependencies..."
pip install flask requests blake3 cryptography

# IoT-Specific Optimizations
if [ "$NODE_TYPE" = "IOT" ]; then
    echo "Applying IoT Node Optimizations..."
    
    # Remove unused packages to save space
    sudo apt-get remove -y man-db && sudo apt-get autoremove -y

    # Apply power-saving configurations
    echo "Setting CPU to low-power mode..."
    echo "powersave" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

    # Reduce SWAP Usage (for memory optimization)
    sudo sysctl vm.swappiness=10
fi

# Install IPFS (If full blockchain node)
if [ "$NODE_TYPE" = "BLOCKCHAIN" ]; then
    echo "Installing IPFS for Blockchain Node..."
    wget https://dist.ipfs.io/go-ipfs/v0.10.0/go-ipfs_v0.10.0_linux-amd64.tar.gz
    tar xvfz go-ipfs_v0.10.0_linux-amd64.tar.gz
    sudo mv go-ipfs/ipfs /usr/local/bin/ipfs
    ipfs init
    echo "IPFS successfully installed and initialized."
fi

# Final Setup Confirmation
echo "============================="
echo "Blockchain Node Setup Complete!"
echo "Node Type: $NODE_TYPE"
echo "Max Memory: $MAX_MEMORY_MB MB"
echo "Low Power Mode: $LOW_POWER_MODE"
echo "============================="

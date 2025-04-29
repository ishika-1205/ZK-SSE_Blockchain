#!/bin/bash

echo "============================="
echo "Setting up IPFS Node..."
echo "============================="

# System Parameters for IoT vs. Full Nodes
export NODE_TYPE="BLOCKCHAIN"
export MAX_MEMORY_MB=1024  # Default memory allocation for full nodes

# Detect IoT Device Based on Hardware Specs
RAM_SIZE_MB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
if [ "$RAM_SIZE_MB" -lt 512000 ]; then  # If less than 512MB RAM, classify as IoT
    export NODE_TYPE="IOT"
    export MAX_MEMORY_MB=256
    echo "IoT Device Detected - Applying IoT IPFS Optimizations..."
else
    echo "Full Blockchain Node Detected - Setting up Full IPFS Configuration..."
fi

# Install Core Dependencies
echo "Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

# Install IPFS Only if This is a Full Blockchain Node
if [ "$NODE_TYPE" = "BLOCKCHAIN" ]; then
    echo "Installing IPFS for Full Blockchain Node..."
    
    # Download and install IPFS
    wget https://dist.ipfs.io/go-ipfs/v0.10.0/go-ipfs_v0.10.0_linux-amd64.tar.gz
    tar xvfz go-ipfs_v0.10.0_linux-amd64.tar.gz
    sudo mv go-ipfs/ipfs /usr/local/bin/ipfs

    # Initialize IPFS Node
    ipfs init

    # Enable File Caching & Optimization
    ipfs config --json Datastore.StorageMax "\"5GB\""
    ipfs config --json Datastore.GCPeriod "\"24h\""
    ipfs config --json Datastore.BloomFilterSize "\"1048576\""

    echo "IPFS successfully installed and configured for Full Node."
else
    echo "Skipping Full IPFS Installation - IoT Device Mode Enabled."
fi

# IoT Optimizations
if [ "$NODE_TYPE" = "IOT" ]; then
    echo "Configuring IPFS for IoT Device (Client Mode)..."

    # Install IPFS client utilities only
    sudo apt-get install -y ipfs-clients
    
    # Reduce Memory & Bandwidth Usage
    echo "Disabling IPFS Daemon on IoT Device..."
    systemctl stop ipfs
    systemctl disable ipfs

    echo "Optimizing IPFS Retrieval for IoT..."
    ipfs config --json Gateway.NoFetch "\"true\""
    ipfs config --json Gateway.DisableRedirect "\"true\""

    echo "IPFS Client Mode Enabled for IoT Node."
fi

# Final Setup Confirmation
echo "============================="
echo "IPFS Setup Complete!"
echo "Node Type: $NODE_TYPE"
echo "Max Memory: $MAX_MEMORY_MB MB"
echo "============================="

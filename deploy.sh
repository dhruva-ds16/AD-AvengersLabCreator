#!/bin/bash

# Avengers AD Lab Creator Deployment Script
# Run this script on your Proxmox node

echo "===== Avengers AD Lab Creator ====="
echo "Starting deployment process..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $python_version"

# Install dependencies if needed
echo "Checking and installing dependencies..."
apt update -y
apt install -y python3-pip git

# Install Python requirements
echo "Installing Python requirements..."
pip3 install -r requirements.txt

# Check if ISOs exist
echo "Checking for required ISOs..."
iso_dir="/var/lib/vz/template/iso"
win_iso="$iso_dir/Windows_Server_2022_EVAL.iso"
virtio_iso="$iso_dir/virtio-win.iso"

if [ ! -f "$win_iso" ]; then
  echo "Windows Server ISO not found at $win_iso"
  echo "Please download it manually and place it in $iso_dir"
  exit 1
fi

if [ ! -f "$virtio_iso" ]; then
  echo "VirtIO drivers ISO not found at $virtio_iso"
  echo "Please download it manually and place it in $iso_dir"
  exit 1
fi

# Run the deployment script
echo "Starting deployment..."
python3 create_ad_environment.py

echo "Deployment process completed!"
echo "Please check the logs for any errors."
echo "===== End of Deployment =====" 
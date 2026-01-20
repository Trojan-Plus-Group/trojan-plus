#!/bin/bash
set -e

# Define image name (consistent with the one on Docker Hub)
IMAGE_NAME="trojanplusgroup/centos-build:debian"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "Building Docker image for linux/amd64..."
# Ensure we build for amd64 architecture even on ARM/M1/M2 Macs
docker build --platform linux/amd64 -t $IMAGE_NAME -f scripts/Dockerfile .

echo "Docker image '$IMAGE_NAME' built successfully for linux/amd64."
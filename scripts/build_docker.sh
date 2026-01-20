#!/bin/bash
set -e

# Define image name
IMAGE_NAME="trojan-builder"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "Building Docker image..."
docker build --platform linux/amd64 -t $IMAGE_NAME -f scripts/Dockerfile .
echo "Docker image '$IMAGE_NAME' built successfully."

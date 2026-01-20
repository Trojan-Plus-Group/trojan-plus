#!/bin/bash
set -e

# Define image name
IMAGE_TAG="trojanplusgroup/centos-build:debian"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "Building and pushing Docker image for linux/amd64..."
# Using buildx to ensure correct architecture for remote repository
docker buildx build --platform linux/amd64 -t $IMAGE_TAG -f scripts/Dockerfile --push .

echo "Docker image '$IMAGE_TAG' pushed successfully for linux/amd64."

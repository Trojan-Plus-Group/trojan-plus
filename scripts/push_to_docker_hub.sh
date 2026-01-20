#!/bin/bash
set -e

# This script pushes the locally built image to Docker Hub.
# TARGET: https://hub.docker.com/r/trojanplusgroup/centos-build
IMAGE_TAG="trojanplusgroup/centos-build:debian"

# NOTE:
# 1. This script does NOT build the image. Run ./scripts/build_docker.sh first.
# 2. You MUST be logged in to Docker Hub with an account that has 
#    write access to the 'trojanplusgroup' organization.
#    Run 'docker login' before executing this script.

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "Pushing image '$IMAGE_TAG' to Docker Hub..."
docker push $IMAGE_TAG

echo "Docker image '$IMAGE_TAG' pushed successfully."
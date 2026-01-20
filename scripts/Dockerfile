FROM debian:bookworm-slim

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build and test dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libboost-all-dev \
        libssl-dev \
        libmariadb-dev \
        libmimalloc-dev \
        git \
        python3 \
        python3-pip \
        sudo \
        iproute2 \
        net-tools \
        curl \
        wget \
        lsof \
        netcat-openbsd \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages PySocks psutil dnspython

# Set working directory
WORKDIR /usr/src/trojan

# By default, provide a shell
CMD ["/bin/bash"]

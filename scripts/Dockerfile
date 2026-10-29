# Debian trixie ships Boost 1.83 and CMake 3.31, which satisfy the
# Boost >= 1.77 and CMake >= 3.20 requirements in CMakeLists.txt.
FROM debian:trixie-slim

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build and test dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libboost-all-dev \
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
    && pip3 install --break-system-packages PySocks psutil dnspython aioquic

# Set working directory
WORKDIR /usr/src/trojan

# By default, provide a shell
CMD ["/bin/bash"]

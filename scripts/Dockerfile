FROM alpine:3.20

# Add community repository for mimalloc
RUN echo "http://dl-cdn.alpinelinux.org/alpine/v3.20/community" >> /etc/apk/repositories

# Install build and test dependencies
# linux-headers is often required for Boost/system compilation
RUN apk add --no-cache \
        bash \
        curl \
        openssl \
        build-base \
        linux-headers \
        cmake \
        boost-dev \
        openssl-dev \
        mariadb-connector-c-dev \
        mimalloc-dev \
        git \
        python3 \
        py3-pip \
        lsof \
        netcat-openbsd \
        sudo \
        iproute2 \
        net-tools \
    && pip3 install --break-system-packages PySocks psutil dnspython

# Set working directory
WORKDIR /usr/src/trojan

# By default, provide a shell
CMD ["/bin/bash"]
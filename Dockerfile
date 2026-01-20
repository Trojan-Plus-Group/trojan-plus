FROM alpine:3.20

COPY . trojan
RUN echo "http://dl-cdn.alpinelinux.org/alpine/v3.20/community" >> /etc/apk/repositories \
    && apk add --no-cache --virtual .build-deps \
        build-base \
        cmake \
        boost-dev \
        openssl-dev \
        mariadb-connector-c-dev \
        mimalloc-dev \
    && (cd trojan && cmake -DENABLE_MIMALLOC=ON . && make -j $(nproc) && strip -s trojan \
    && mv trojan /usr/local/bin) \
    && rm -rf trojan \
    && apk del .build-deps \
    && apk add --no-cache --virtual .trojan-rundeps \
        libstdc++ \
        boost-system \
        boost-program_options \
        mariadb-connector-c \
        mimalloc

WORKDIR /config
CMD ["trojan", "config.json"]

########################################################################################################################
# Zeek and Spicy

# use the handy-dandy zeek-docker.sh or manually as per these examples

# Monitor a local network interface with Zeek:
#
#   docker run --rm \
#     -v "$(pwd):/zeek-logs" \
#     --network host \
#     --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=IPC_LOCK \
#     mmguero/zeek:latest \
#     zeekcap -i enp6s0 local

# Analyze a PCAP file with Zeek:
#
#   docker run --rm \
#     -v "$(pwd):/zeek-logs" \
#     -v "/path/containing/pcap:/data:ro" \
#     mmguero/zeek:latest \
#     zeek -C -r /data/foobar.pcap local

# Use a custom policy:
#
#   docker run --rm \
#     -v "$(pwd):/zeek-logs" \
#     -v "/path/containing/pcap:/data:ro" \
#     -v "/path/containing/policy/local-example.zeek:/opt/zeek/share/zeek/site/local.zeek:ro" \
#     mmguero/zeek:latest \
#     zeek -C -r /data/foobar.pcap local

########################################################################################################################
FROM debian:12-slim as build

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

# for build
ARG ZEEK_VERSION=6.0.1
ENV ZEEK_VERSION $ZEEK_VERSION

ARG ZEEK_DBG=0
ENV ZEEK_DBG $ZEEK_DBG

ARG BUILD_JOBS=4
ENV BUILD_JOBS $BUILD_JOBS

ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1
ENV CMAKE_C_COMPILER clang-14
ENV CMAKE_CXX_COMPILER clang++-14
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
        bison \
        ca-certificates \
        ccache \
        cmake \
        curl \
        flex \
        clang \
        git \
        libfl-dev \
        libgoogle-perftools4 \
        libgoogle-perftools-dev \
        libkrb5-3 \
        libkrb5-dev \
        libmaxminddb-dev \
        libpcap-dev \
        libssl-dev \
        libtcmalloc-minimal4 \
        make \
        ninja-build \
        python3 \
        python3-dev \
        python3-git \
        python3-semantic-version \
        sudo \
        swig \
        zlib1g-dev && \
    mkdir -p /usr/share/src/zeek "${CCACHE_DIR}" && \
        cd /usr/share/src && \
        ( curl -sSL "https://download.zeek.org/zeek-${ZEEK_VERSION}.tar.gz" | tar xzf - -C ./zeek --strip-components 1 ) && \
        cd /usr/share/src/zeek && \
        [ "$ZEEK_DBG" = "1" ] && \
            ./configure --prefix=/opt/zeek --generator=Ninja --ccache --enable-perftools --enable-debug || \
            ./configure --prefix=/opt/zeek --generator=Ninja --ccache --enable-perftools && \
        ninja -C build -j "${BUILD_JOBS}" && \
        cd ./build && \
        cpack -G DEB

########################################################################################################################
FROM debian:12-slim as base


LABEL maintainer="mero.mero.guero@gmail.com"
LABEL org.opencontainers.image.authors='mero.mero.guero@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.source='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.title='ghcr.io/mmguero/zeek'
LABEL org.opencontainers.image.description='Dockerized Zeek and Spicy'


ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

# put Zeek and Spicy in PATH
ENV ZEEK_DIR "/opt/zeek"
ENV PATH "${ZEEK_DIR}/bin:${PATH}"

# for build
ARG ZEEK_DBG=0
ENV ZEEK_DBG $ZEEK_DBG
ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1
ENV SPICY_ZKG_PROCESSES 1
ENV CMAKE_C_COMPILER clang-14
ENV CMAKE_CXX_COMPILER clang++-14

COPY --from=build /usr/share/src/zeek/build/*.deb /tmp/zeek-deb/

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
        binutils \
        ca-certificates \
        ccache \
        cmake \
        curl \
        file \
        clang \
        git \
        libcap2-bin \
        libfl2 \
        libgoogle-perftools4 \
        libkrb5-3 \
        libmaxminddb0 \
        libpcap-dev \
        libpcap0.8 \
        libssl-dev \
        libssl3 \
        libtcmalloc-minimal4 \
        make \
        openssl \
        procps \
        psmisc \
        python3 \
        python3-git \
        python3-semantic-version \
        rsync \
        tini \
        xxd && \
    dpkg -i /tmp/zeek-deb/*.deb && \
    apt-get -f install -q -y --no-install-recommends && \
    zkg autoconfig --force && \
    if [ "$ZEEK_DBG" = "1" ]; then \
        ( find "${ZEEK_DIR}"/lib "${ZEEK_DIR}"/var/lib/zkg \( -path "*/build/*" -o -path "*/CMakeFiles/*" \) -type f -name "*.*" -print0 | xargs -0 -I XXX bash -c 'file "XXX" | sed "s/^.*:[[:space:]]//" | grep -Pq "(ELF|gzip)" && rm -f "XXX"' || true ) ; \
        ( find "${ZEEK_DIR}"/var/lib/zkg/clones -type d -name .git -execdir bash -c "pwd; du -sh; git pull --depth=1 --ff-only; git reflog expire --expire=all --all; git tag -l | xargs -r git tag -d; git gc --prune=all; du -sh" \; ) ; \
        rm -rf "${ZEEK_DIR}"/var/lib/zkg/scratch ; \
        rm -rf "${ZEEK_DIR}"/lib/zeek/python/zeekpkg/__pycache__ ; \
        ( find "${ZEEK_DIR}/" -type f -exec file "{}" \; | grep -Pi "ELF 64-bit.*not stripped" | sed 's/:.*//' | xargs -l -r strip --strip-unneeded ) ; \
        ( find "${ZEEK_DIR}"/lib/zeek/plugins/packages -type f -name "*.hlto" -exec chmod 755 "{}" \; || true ) ; \
    fi && \
    echo "@load packages" >> "${ZEEK_DIR}"/share/zeek/site/local.zeek && \
    cd /usr/lib/locale && \
      ( ls | grep -Piv "^(en|en_US|en_US\.utf-?8|C\.utf-?8)$" | xargs -l -r rm -rf ) && \
    cd /tmp && \
    apt-get -q -y autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# configure unprivileged user and runtime parameters
ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "zeekcap"
ENV PGROUP "zeekcap"
ENV PUSER_PRIV_DROP true

ARG ZEEK_LOGS_DIR=/zeek-logs
ENV ZEEK_LOGS_DIR $ZEEK_LOGS_DIR

ENV ZEEK_DISABLE_HASH_ALL_FILES ""
ENV ZEEK_DISABLE_LOG_PASSWORDS ""
ENV ZEEK_DISABLE_SSL_VALIDATE_CERTS ""
ENV ZEEK_DISABLE_TRACK_ALL_ASSETS ""
ENV ZEEK_DISABLE_SPICY_DHCP "true"
ENV ZEEK_DISABLE_SPICY_DNS "true"
ENV ZEEK_DISABLE_SPICY_FACEFISH ""
ENV ZEEK_DISABLE_SPICY_HTTP "true"
ENV ZEEK_DISABLE_SPICY_IPSEC ""
ENV ZEEK_DISABLE_SPICY_LDAP ""
ENV ZEEK_DISABLE_SPICY_OPENVPN ""
ENV ZEEK_DISABLE_SPICY_STUN ""
ENV ZEEK_DISABLE_SPICY_TAILSCALE ""
ENV ZEEK_DISABLE_SPICY_TFTP ""
ENV ZEEK_DISABLE_SPICY_WIREGUARD ""

ADD https://raw.githubusercontent.com/mmguero/docker/master/shared/docker-uid-gid-setup.sh /usr/local/bin/docker-uid-gid-setup.sh
ADD login.zeek "${ZEEK_DIR}"/share/zeek/site/
ADD entrypoint.sh /usr/local/bin/

RUN chmod 755 /usr/local/bin/docker-uid-gid-setup.sh && \
    groupadd --gid ${DEFAULT_GID} ${PUSER} && \
    useradd -m --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} && \
    mkdir -p "${ZEEK_LOGS_DIR}" "${ZEEK_DIR}"/share/zeek/site/intel && \
    touch "${ZEEK_DIR}"/share/zeek/site/intel/__load__.zeek && \
    chown -R ${PUSER}:${PGROUP} "${ZEEK_LOGS_DIR}" "${ZEEK_DIR}"/share/zeek/site/intel && \
    # make a setcap copy of zeek (zeekcap) for listening on an interface
    cp "${ZEEK_DIR}"/bin/zeek "${ZEEK_DIR}"/bin/zeekcap && \
    chown root:${PGROUP} "${ZEEK_DIR}"/bin/zeekcap && \
    setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' "${ZEEK_DIR}"/bin/zeekcap

VOLUME "${ZEEK_DIR}/share/zeek/site/intel"

WORKDIR "${ZEEK_LOGS_DIR}"

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-uid-gid-setup.sh", "/usr/local/bin/entrypoint.sh"]

########################################################################################################################
FROM base as plus


LABEL maintainer="mero.mero.guero@gmail.com"
LABEL org.opencontainers.image.authors='mero.mero.guero@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.source='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.title='ghcr.io/mmguero/zeek:plus'
LABEL org.opencontainers.image.description='Dockerized Zeek and Spicy with extra plugins'


ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

# put Zeek and Spicy in PATH
ENV ZEEK_DIR "/opt/zeek"
ENV PATH "${ZEEK_DIR}/bin:${PATH}"

# for build
ARG ZEEK_DBG=0
ENV ZEEK_DBG $ZEEK_DBG
ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1
ENV SPICY_ZKG_PROCESSES 1
ENV CMAKE_C_COMPILER clang-14
ENV CMAKE_CXX_COMPILER clang++-14

RUN curl -fsSL -o /tmp/zeek_install_plugins.sh "https://raw.githubusercontent.com/mmguero-dev/Malcolm/development/shared/bin/zeek_install_plugins.sh" && \
    bash /tmp/zeek_install_plugins.sh && \
    if [ "$ZEEK_DBG" = "1" ]; then \
        ( find "${ZEEK_DIR}"/lib "${ZEEK_DIR}"/var/lib/zkg \( -path "*/build/*" -o -path "*/CMakeFiles/*" \) -type f -name "*.*" -print0 | xargs -0 -I XXX bash -c 'file "XXX" | sed "s/^.*:[[:space:]]//" | grep -Pq "(ELF|gzip)" && rm -f "XXX"' || true ) ; \
        ( find "${ZEEK_DIR}"/var/lib/zkg/clones -type d -name .git -execdir bash -c "pwd; du -sh; git pull --depth=1 --ff-only; git reflog expire --expire=all --all; git tag -l | xargs -r git tag -d; git gc --prune=all; du -sh" \; ) ; \
        rm -rf "${ZEEK_DIR}"/var/lib/zkg/scratch ; \
        rm -rf "${ZEEK_DIR}"/lib/zeek/python/zeekpkg/__pycache__ ; \
        ( find "${ZEEK_DIR}/" -type f -exec file "{}" \; | grep -Pi "ELF 64-bit.*not stripped" | sed 's/:.*//' | xargs -l -r strip --strip-unneeded ) ; \
        ( find "${ZEEK_DIR}"/lib/zeek/plugins/packages -type f -name "*.hlto" -exec chmod 755 "{}" \; || true ) ; \
    fi && \
    rm -rf /tmp/zeek_install_plugins.sh

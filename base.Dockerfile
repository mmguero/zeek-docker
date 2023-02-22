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

FROM debian:bullseye-slim

LABEL maintainer="mero.mero.guero@gmail.com"
LABEL org.opencontainers.image.authors='mero.mero.guero@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.source='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.title='ghcr.io/mmguero/zeek'
LABEL org.opencontainers.image.description='Dockerized Zeek and Spicy'

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

# for download and install
ARG ZEEK_LTS=
ARG ZEEK_VERSION=5.1.3-0

ENV ZEEK_LTS $ZEEK_LTS
ENV ZEEK_VERSION $ZEEK_VERSION

# for build
ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1

# put Zeek and Spicy in PATH
ENV ZEEK_DIR "/opt/zeek"
ENV PATH "${ZEEK_DIR}/bin:${PATH}"

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
      bison \
      ca-certificates \
      ccache \
      cmake \
      curl \
      file \
      flex \
      g++ \
      gcc \
      git \
      gnupg2 \
      jq \
      less \
      libatomic1 \
      libcap2-bin \
      libfl-dev \
      libgoogle-perftools4 \
      libkrb5-3 \
      libmaxminddb-dev \
      libmaxminddb0 \
      libpcap-dev \
      libpcap0.8 \
      libssl-dev \
      libtcmalloc-minimal4 \
      libunwind8 \
      locales-all \
      make \
      moreutils \
      ninja-build \
      procps \
      psmisc \
      python3 \
      python3-git \
      python3-pip \
      python3-semantic-version \
      python3-setuptools \
      python3-wheel \
      swig \
      tini \
      vim-tiny \
      zlib1g-dev && \
    mkdir -p /tmp/zeek-packages && \
      cd /tmp/zeek-packages && \
      if [ -n "${ZEEK_LTS}" ]; then ZEEK_LTS="-lts"; fi && export ZEEK_LTS && \
      curl -sSL --remote-name-all \
        "https://download.opensuse.org/repositories/security:/zeek/Debian_11/amd64/libbroker${ZEEK_LTS}-dev_${ZEEK_VERSION}_amd64.deb" \
        "https://download.opensuse.org/repositories/security:/zeek/Debian_11/amd64/zeek${ZEEK_LTS}-core-dev_${ZEEK_VERSION}_amd64.deb" \
        "https://download.opensuse.org/repositories/security:/zeek/Debian_11/amd64/zeek${ZEEK_LTS}-core_${ZEEK_VERSION}_amd64.deb" \
        "https://download.opensuse.org/repositories/security:/zeek/Debian_11/amd64/zeek${ZEEK_LTS}-spicy-dev_${ZEEK_VERSION}_amd64.deb" \
        "https://download.opensuse.org/repositories/security:/zeek/Debian_11/amd64/zeek${ZEEK_LTS}_${ZEEK_VERSION}_amd64.deb" \
        "https://download.opensuse.org/repositories/security:/zeek/Debian_11/amd64/zeekctl${ZEEK_LTS}_${ZEEK_VERSION}_amd64.deb" \
        "https://download.opensuse.org/repositories/security:/zeek/Debian_11/all/zeek${ZEEK_LTS}-client_${ZEEK_VERSION}_all.deb" \
        "https://download.opensuse.org/repositories/security:/zeek/Debian_11/all/zeek${ZEEK_LTS}-zkg_${ZEEK_VERSION}_all.deb" \
        "https://download.opensuse.org/repositories/security:/zeek/Debian_11/all/zeek${ZEEK_LTS}-btest_${ZEEK_VERSION}_all.deb" \
        "https://download.opensuse.org/repositories/security:/zeek/Debian_11/all/zeek${ZEEK_LTS}-btest-data_${ZEEK_VERSION}_all.deb" && \
      dpkg -i ./*.deb && \
    cd /tmp && \
    mkdir -p "${CCACHE_DIR}" && \
    zkg autoconfig --force && \
    echo "@load packages" >> "${ZEEK_DIR}"/share/zeek/site/local.zeek && \
    ( find "${ZEEK_DIR}"/lib "${ZEEK_DIR}"/var/lib/zkg \( -path "*/build/*" -o -path "*/CMakeFiles/*" \) -type f -name "*.*" -print0 | xargs -0 -I XXX bash -c 'file "XXX" | sed "s/^.*:[[:space:]]//" | grep -Pq "(ELF|gzip)" && rm -f "XXX"' || true ) && \
    ( find "${ZEEK_DIR}"/var/lib/zkg/clones -type d -name .git -execdir bash -c "pwd; du -sh; git pull --depth=1 --ff-only; git reflog expire --expire=all --all; git tag -l | xargs -r git tag -d; git gc --prune=all; du -sh" \; ) && \
    rm -rf "${ZEEK_DIR}"/var/lib/zkg/scratch && \
    rm -rf "${ZEEK_DIR}"/lib/zeek/python/zeekpkg/__pycache__ && \
    ( find "${ZEEK_DIR}/" -type f -exec file "{}" \; | grep -Pi "ELF 64-bit.*not stripped" | sed 's/:.*//' | xargs -l -r strip --strip-unneeded ) && \
    ( find "${ZEEK_DIR}"/lib/zeek/plugins/packages -type f -name "*.hlto" -exec chmod 755 "{}" \; || true ) && \
    cd /usr/lib/locale && \
      ( ls | grep -Piv "^(en|en_US|en_US\.utf-?8|C\.utf-?8)$" | xargs -l -r rm -rf ) && \
    cd /tmp && \
    apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/cache/*/*

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

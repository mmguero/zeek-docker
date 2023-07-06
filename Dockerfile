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

FROM debian:12-slim as base

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
ARG ZEEK_RC=
ARG ZEEK_DBG=
ARG ZEEK_VERSION=6.0.0-0

ENV ZEEK_LTS $ZEEK_LTS
ENV ZEEK_RC $ZEEK_RC
ENV ZEEK_DBG $ZEEK_DBG
ENV ZEEK_VERSION $ZEEK_VERSION

# put Zeek and Spicy in PATH
ENV ZEEK_DIR "/opt/zeek"
ENV PATH "${ZEEK_DIR}/bin:${PATH}"

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
        ca-certificates \
        cmake \
        curl \
        g++ \
        libcap2-bin \
        openssl \
        rsync \
        tini && \
    mkdir -p /tmp/zeek-packages && \
      cd /tmp/zeek-packages && \
      if [ -n "${ZEEK_LTS}" ]; then ZEEK_LTS="-lts"; fi && export ZEEK_LTS && \
      if [ -n "${ZEEK_RC}" ]; then ZEEK_RC="-rc"; ln -s -r "${ZEEK_DIR}${ZEEK_RC}" "${ZEEK_DIR}"; fi && export ZEEK_RC && \
        curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/all/zeek${ZEEK_LTS}${ZEEK_RC}-btest-data_6.0.0-0_all.deb" && \
        curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/all/zeek${ZEEK_LTS}${ZEEK_RC}-btest_6.0.0-0_all.deb" && \
        curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/all/zeek${ZEEK_LTS}${ZEEK_RC}-client_6.0.0-0_all.deb" && \
        curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/all/zeek${ZEEK_LTS}${ZEEK_RC}-zkg_6.0.0-0_all.deb" && \
        curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/amd64/libbroker${ZEEK_LTS}${ZEEK_RC}-dev_6.0.0-0_amd64.deb" && \
        curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/amd64/zeek${ZEEK_LTS}${ZEEK_RC}_6.0.0-0_amd64.deb" && \
        curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/amd64/zeek${ZEEK_LTS}${ZEEK_RC}-core_6.0.0-0_amd64.deb" && \
        curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/amd64/zeek${ZEEK_LTS}${ZEEK_RC}-core-dev_6.0.0-0_amd64.deb" && \
        curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/amd64/zeek${ZEEK_LTS}${ZEEK_RC}-spicy-dev_6.0.0-0_amd64.deb" && \
        curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/amd64/zeekctl${ZEEK_LTS}${ZEEK_RC}_6.0.0-0_amd64.deb" && \
        if [ -n "${ZEEK_DBG}" ]; then \
            ZEEK_DBG="-dbgsym" && export ZEEK_DBG && \
            curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/amd64/zeek${ZEEK_LTS}${ZEEK_RC}-core${ZEEK_DBG}_6.0.0-0_amd64.deb" && \
            curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/amd64/zeek${ZEEK_LTS}${ZEEK_RC}-core-dev${ZEEK_DBG}_6.0.0-0_amd64.deb" && \
            curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/amd64/zeek${ZEEK_LTS}${ZEEK_RC}-spicy-dev${ZEEK_DBG}_6.0.0-0_amd64.deb" && \
            curl -fsSL -O -J "https://download.opensuse.org/repositories/security:/zeek/Debian_12/amd64/zeekctl${ZEEK_LTS}${ZEEK_RC}${ZEEK_DBG}_6.0.0-0_amd64.deb"; \
        fi && \
      ( dpkg -i ./*.deb || apt-get -f -q -y --no-install-recommends install ) && \
    cd /tmp && \
    zkg autoconfig --force && \
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

FROM base as plus

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

LABEL maintainer="mero.mero.guero@gmail.com"
LABEL org.opencontainers.image.authors='mero.mero.guero@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.source='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.title='ghcr.io/mmguero/zeek:plus'
LABEL org.opencontainers.image.description='Dockerized Zeek and Spicy with extra plugins'

# for build
ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1

# put Zeek and Spicy in PATH
ENV ZEEK_DIR "/opt/zeek"
ENV PATH "${ZEEK_DIR}/bin:${PATH}"

RUN curl -fsSL -o /tmp/zeek_install_plugins.sh "https://raw.githubusercontent.com/mmguero-dev/Malcolm/development/shared/bin/zeek_install_plugins.sh" && \
    bash /tmp/zeek_install_plugins.sh && \
    rm -rf /tmp/zeek_install_plugins.sh

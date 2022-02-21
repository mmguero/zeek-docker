FROM debian:bullseye-slim as build

ENV DEBIAN_FRONTEND noninteractive

ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1
ENV SRC_BASE_DIR "/usr/local/src"
ENV ZEEK_DIR "/opt/zeek"
ENV ZEEK_PATCH_DIR "${SRC_BASE_DIR}/zeek-patches"
ENV ZEEK_SRC_DIR "${SRC_BASE_DIR}/zeek-${ZEEK_VERSION}"
ENV ZEEK_VERSION "3.0.14"

ENV PATH "${ZEEK_DIR}/bin:${PATH}"

RUN echo "deb http://deb.debian.org/debian bullseye-backports main" >> /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
      binutils \
      bison \
      build-essential \
      ca-certificates \
      ccache \
      cmake \
      curl \
      file \
      flex \
      git \
      gnupg2 \
      google-perftools \
      jq \
      libfl-dev \
      libgoogle-perftools-dev \
      libkrb5-dev \
      libmaxminddb-dev \
      libpcap0.8-dev \
      libssl-dev \
      locales-all \
      make \
      ninja-build \
      patch \
      python3 \
      python3-dev \
      python3-pip \
      python3-setuptools \
      python3-wheel \
      swig \
      zlib1g-dev && \
  pip3 install --no-cache-dir zkg btest pre-commit && \
  cd "${SRC_BASE_DIR}" && \
    curl -sSL "https://old.zeek.org/downloads/zeek-${ZEEK_VERSION}.tar.gz" | tar xzf - -C "${SRC_BASE_DIR}" && \
    cd "./zeek-${ZEEK_VERSION}" && \
    bash -c "for i in ${ZEEK_PATCH_DIR}/* ; do patch -p 1 -r - --no-backup-if-mismatch < \$i || true; done" && \
    ./configure --prefix="${ZEEK_DIR}" --generator=Ninja --ccache --enable-perftools && \
    cd build && \
    ninja && \
    ninja install && \
    zkg autoconfig && \
    bash -c "find ${ZEEK_DIR}/lib -type d -name CMakeFiles -exec rm -rf '{}' \; 2>/dev/null || true" && \
    bash -c "file ${ZEEK_DIR}/{lib,bin}/* ${ZEEK_DIR}/lib/zeek/plugins/packages/*/lib/* ${ZEEK_DIR}/lib/zeek/plugins/*/lib/* | grep 'ELF 64-bit' | sed 's/:.*//' | xargs -l -r strip -v --strip-unneeded"

FROM debian:bullseye-slim

LABEL maintainer="mero.mero.guero@gmail.com"
LABEL org.opencontainers.image.authors='mero.mero.guero@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.source='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.title='ghcr.io/mmguero/zeek'
LABEL org.opencontainers.image.description='Dockerized Zeek'

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

# for download and install
ARG ZEEK_LTS=
ARG ZEEK_VERSION=3.0.14

ENV ZEEK_LTS $ZEEK_LTS
ENV ZEEK_VERSION $ZEEK_VERSION

# for build
ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1

# put Zeek in PATH
ENV ZEEK_DIR "/opt/zeek"
ENV PATH "${ZEEK_DIR}/bin:${PATH}"

COPY --from=build ${ZEEK_DIR} ${ZEEK_DIR}

RUN export DEBARCH=$(dpkg --print-architecture) && \
    apt-get -q update && \
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
      libgoogle-perftools-dev \
      linux-headers-$DEBARCH \
      less \
      libcap2-bin \
      libfl-dev \
      libmaxminddb-dev \
      libmaxminddb0 \
      libpcap-dev \
      libpcap0.8 \
      libssl-dev \
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
      vim-tiny \
      zlib1g-dev && \
    cd /tmp && \
    mkdir -p "${CCACHE_DIR}" && \
    pip3 install --no-cache-dir zkg btest pre-commit && \
    zkg autoconfig --force && \
    echo "@load packages" >> "${ZEEK_DIR}"/share/zeek/site/local.zeek && \
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

ADD https://raw.githubusercontent.com/mmguero/docker/master/shared/docker-uid-gid-setup.sh /usr/local/bin/docker-uid-gid-setup.sh
ADD entrypoint.sh /usr/local/bin/

RUN chmod 755 /usr/local/bin/docker-uid-gid-setup.sh && \
    groupadd --gid ${DEFAULT_GID} ${PUSER} && \
    useradd -m --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} && \
    mkdir -p "${ZEEK_LOGS_DIR}" && \
    chown -R ${PUSER}:${PGROUP} "${ZEEK_LOGS_DIR}" && \
    # make a setcap copy of zeek (zeekcap) for listening on an interface
    cp "${ZEEK_DIR}"/bin/zeek "${ZEEK_DIR}"/bin/zeekcap && \
    chown root:${PGROUP} "${ZEEK_DIR}"/bin/zeekcap && \
    setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' "${ZEEK_DIR}"/bin/zeekcap

WORKDIR "${ZEEK_LOGS_DIR}"

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh", "/usr/local/bin/entrypoint.sh"]

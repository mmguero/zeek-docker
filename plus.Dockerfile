FROM ghcr.io/mmguero/zeek:latest

LABEL maintainer="mero.mero.guero@gmail.com"
LABEL org.opencontainers.image.authors='mero.mero.guero@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.source='https://github.com/mmguero/zeek-docker'
LABEL org.opencontainers.image.title='ghcr.io/mmguero/zeek-plus'
LABEL org.opencontainers.image.description='Dockerized Zeek and Spicy with extra plugins'

ADD https://raw.githubusercontent.com/mmguero-dev/Malcolm/development/shared/bin/zeek_install_plugins.sh /tmp/zeek_install_plugins.sh

RUN bash /tmp/zeek_install_plugins.sh || true

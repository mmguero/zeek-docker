FROM ghcr.io/mmguero/zeek:latest

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
    ( find "${ZEEK_DIR}"/lib "${ZEEK_DIR}"/var/lib/zkg \( -path "*/build/*" -o -path "*/CMakeFiles/*" \) -type f -name "*.*" -print0 | xargs -r -0 -I XXX bash -c 'file "XXX" | sed "s/^.*:[[:space:]]//" | grep -Pq "(ELF|gzip)" && rm -f "XXX"' || true ) && \
    ( find "${ZEEK_DIR}"/var/lib/zkg/clones -type d -name .git -execdir bash -c "pwd; du -sh; git pull --depth=1 --ff-only; git reflog expire --expire=all --all; git tag -l | xargs -r git tag -d; git gc --prune=all; du -sh" \; ) && \
    rm -rf /tmp/zeek_install_plugins.sh \
           "${ZEEK_DIR}"/var/lib/zkg/scratch \
           "${ZEEK_DIR}"/lib/zeek/python/zeekpkg/__pycache__ && \
    ( find "${ZEEK_DIR}/" "${SPICY_DIR}/" -type f -exec file "{}" \; | grep -Pi "ELF 64-bit.*not stripped" | sed 's/:.*//' | xargs -r -l -r strip --strip-unneeded ) && \
    ( find "${ZEEK_DIR}"/lib/zeek/plugins/packages -type f -name "*.hlto" -exec chmod 755 "{}" \; || true )

FROM ghcr.io/hotio/base@sha256:d1028a84da6b618f947ff7506b28763ce8e9238d7f47da8e59de8553f763004a

ARG DEBIAN_FRONTEND="noninteractive"

ENV VPN_ENABLED="false" VPN_LAN_NETWORK="" VPN_CONF="wg0"

EXPOSE 8080

RUN ln -s "${CONFIG_DIR}/app" "${APP_DIR}/qBittorrent"

ARG FULL_VERSION

RUN apt update && \
    apt install -y --no-install-recommends --no-install-suggests \
        gnupg && \
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:11371 --recv-keys 7CA69FC4 && echo "deb http://ppa.launchpad.net/qbittorrent-team/qbittorrent-unstable/ubuntu focal main" | tee /etc/apt/sources.list.d/qbitorrent.list && \
    apt update && \
    apt install -y --no-install-recommends --no-install-suggests \
        qbittorrent-nox=${FULL_VERSION} \
        ipcalc \
        iptables \
        iproute2 \
        openresolv \
        wireguard-tools && \
# clean up
    apt purge -y gnupg && \
    apt autoremove -y && \
    apt clean && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*

COPY root/ /
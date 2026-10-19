FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus-user-session \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1001 --shell /bin/bash smoke \
    && mkdir -p /var/lib/systemd/linger && touch /var/lib/systemd/linger/smoke
COPY scripts /opt/sshgate/scripts
COPY packaging /opt/sshgate/packaging
COPY sshgate-executor /usr/local/bin/sshgate-executor
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

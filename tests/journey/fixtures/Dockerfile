ARG UBUNTU_IMAGE
FROM ${UBUNTU_IMAGE}
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus openssh-server openssh-client sudo make gcc libc6-dev \
    git ca-certificates python3 curl iproute2 procps && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash operator && useradd -m -s /bin/bash user \
    && echo 'operator ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/operator \
    && chmod 0440 /etc/sudoers.d/operator \
    && passwd -d user && rm -f /etc/ssh/ssh_host_* \
    && systemctl mask systemd-resolved.service systemd-networkd.service \
    && mkdir -p /run/sshd /opt/journey
COPY go/ /usr/local/go/
COPY vendor/ /opt/journey/vendor/
COPY source.bundle fake-telegram /opt/journey/
COPY fixtures/ /opt/journey/fixtures/
ENV PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b

ARG UBUNTU_MIRROR=

RUN if [ -n "$UBUNTU_MIRROR" ]; then \
        sed -i \
            -e "s|http://archive.ubuntu.com/ubuntu|$UBUNTU_MIRROR|g" \
            -e "s|http://security.ubuntu.com/ubuntu|$UBUNTU_MIRROR|g" \
            /etc/apt/sources.list.d/ubuntu.sources; \
    fi \
    && apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=20 update \
    && apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=20 \
        install -y --no-install-recommends openssh-server sudo \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/sh sshw \
    && echo "sshw:sshw-integration-password" | chpasswd \
    && echo "root:root-integration-password" | chpasswd \
    && echo "sshw ALL=(root) ALL" > /etc/sudoers.d/sshw \
    && chmod 0440 /etc/sudoers.d/sshw \
    && mkdir -p /run/sshd \
    && ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e", "-o", "ListenAddress=0.0.0.0", "-o", "PasswordAuthentication=yes", "-o", "PubkeyAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "PermitRootLogin=no", "-o", "UsePAM=no", "-o", "LogLevel=ERROR"]

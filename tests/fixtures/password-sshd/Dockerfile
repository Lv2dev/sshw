FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/sh sshw \
    && echo "sshw:sshw-integration-password" | chpasswd \
    && mkdir -p /run/sshd \
    && ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e", "-o", "ListenAddress=0.0.0.0", "-o", "PasswordAuthentication=yes", "-o", "PubkeyAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "PermitRootLogin=no", "-o", "UsePAM=no", "-o", "LogLevel=ERROR"]

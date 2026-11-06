# Build with BASE set to the same pinned distro as its package build job.
ARG BASE
FROM ${BASE}
ARG KIND
RUN if [ "$KIND" = deb ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
          systemd systemd-sysv dbus udev polkitd libpam-systemd dbus-user-session \
          swtpm tpm2-abrmd libtss2-tcti-tabrmd0 libtss2-tcti-swtpm0t64 libfido2-tools python3 passwd; \
    else \
        dnf install -y systemd systemd-udev dbus-daemon polkit pam \
          swtpm tpm2-abrmd tpm2-tss fido2-tools python3 shadow-utils util-linux; \
    fi
ENV container=docker
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

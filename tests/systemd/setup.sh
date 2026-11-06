#!/bin/sh
# Run inside the disposable booted container before systemd_lifecycle.py.
set -eu
[ -f /run/systemd/container ]
[ -c /dev/uhid ]
mkdir -p /var/lib/fidophir-test-tpm
cat > /etc/systemd/system/fidophir-test-tpm.service <<'UNIT'
[Unit]
Description=Disposable test TPM simulator
[Service]
ExecStart=/usr/bin/swtpm socket --tpm2 --tpmstate dir=/var/lib/fidophir-test-tpm --server type=tcp,port=2321,bindaddr=127.0.0.1 --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 --flags not-need-init,startup-clear
UNIT
# The test daemon uses the real resource manager over the system bus, so the
# packaged service keeps its AF_UNIX restriction and private network intact.
cat > /etc/systemd/system/fidophir-test-abrmd.service <<'UNIT'
[Unit]
Description=Disposable test TPM resource manager
Requires=fidophir-test-tpm.service
After=fidophir-test-tpm.service dbus.service
[Service]
Type=dbus
BusName=com.intel.tss2.Tabrmd
User=tss
Group=tss
ExecStart=/usr/sbin/tpm2-abrmd --tcti=swtpm:host=127.0.0.1,port=2321
UNIT
systemctl daemon-reload
systemctl start systemd-udevd.service dbus.service systemd-logind.service polkit.service
systemctl start fidophir-test-tpm.service
# Type=simple reports started before the simulator binds its socket.
python3 - <<'PYREADY'
import socket
import time
for attempt in range(100):
    try:
        with socket.create_connection(('127.0.0.1', 2321), timeout=0.1):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit('TPM simulator did not open its socket')
PYREADY
systemctl start fidophir-test-abrmd.service
# Package setup will reload the installed rules and trigger UHID itself.
udevadm control --ping

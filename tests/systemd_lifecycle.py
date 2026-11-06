#!/usr/bin/python3
"""Test a built package in a disposable, booted systemd container.

Requires the systemd-tests package variant, a running tpm2-abrmd backed by
swtpm, and UHID, with real udev, logind and polkit.
No service, user manager, package metadata or desktop bus is replaced.
"""
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import sys
import time


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def wait(predicate):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError('systemd lifecycle assertion timed out')


def active(unit):
    return subprocess.run(['systemctl', '--quiet', 'is-active', unit]).returncode == 0


def pid(unit):
    return run('systemctl', 'show', '-p', 'MainPID', '--value', unit)


def ready(uid):
    unit = f'fidophir@{uid}.service'
    device = Path(f'/dev/fidophir-{uid}')
    if not active(unit):
        return False
    if not device.exists():
        # Docker snapshots /dev at startup; create only the real kernel node.
        # Ownership and the user-facing symlink must still come from real udev.
        for entry in Path('/sys/class/hidraw').glob('hidraw*'):
            try:
                properties = (entry / 'device/uevent').read_text().splitlines()
            except FileNotFoundError:
                continue
            if 'HID_PHYS=fidophir-v2' not in properties or f'HID_UNIQ={uid}' not in properties:
                continue
            node = Path('/dev') / entry.name
            if not node.exists():
                major, minor = map(int, (entry / 'dev').read_text().split(':'))
                os.mknod(node, stat.S_IFCHR | 0o600, os.makedev(major, minor))
            run('udevadm', 'trigger', '--action=add', '--settle', str(entry))
        return False
    # Inspect the daemon's real CTAP GetInfo through the packaged udev symlink.
    # This also verifies the intended user can open the device.
    try:
        result = subprocess.run(['runuser', '-u', f'key{uid}', '--', 'fido2-token', '-I', str(device)],
                                capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0 and 'FIDO_2_1' in result.stdout


def main(package):
    assert os.geteuid() == 0 and Path('/run/systemd/container').exists(), 'use a disposable booted container'
    assert not Path('/usr/libexec/fidophir').exists(), 'requires a clean test container'
    package = Path(package).resolve(strict=True)
    deb = package.suffix == '.deb'
    install = ['apt-get', 'install', '-y', str(package)] if deb else ['dnf', 'install', '-y', str(package)]
    reinstall = ['apt-get', 'install', '--reinstall', '-y', str(package)] if deb else ['dnf', 'reinstall', '-y', str(package)]
    remove = ['dpkg', '--remove', 'fidophir'] if deb else ['dnf', 'remove', '-y', 'fidophir']
    for uid in (1000, 1001):
        run('useradd', '--uid', str(uid), '--create-home', f'key{uid}')
    # Real user managers exercise the installed user@ template dependency.
    run('systemctl', 'start', 'user@1000.service')
    Path('/usr/sbin/policy-rc.d').unlink(missing_ok=True)
    run(*install)
    wait(lambda: ready(1000))
    assert active('systemd-logind.service') and active('polkit.service')
    denied = subprocess.run(['runuser', '-u', 'key1000', '--', 'setsid',
                             'fido2-token', '-S', '/dev/fidophir-1000'],
                            input='1234\n1234\n', text=True, capture_output=True, timeout=30)
    assert denied.returncode != 0, 'PIN setup must require an eligible graphical session'
    assert 'no eligible desktop session' in run(
        'journalctl', '-u', 'fidophir@1000.service', '-b', '--no-pager'), denied.stderr
    owner = pwd.getpwnam('fidophir').pw_uid
    state = Path('/var/lib/fidophir-users/1000')
    assert state.stat().st_uid == owner and state.stat().st_mode & 0o777 == 0o700
    device = Path('/dev/fidophir-1000')
    assert device.stat().st_uid == 1000 and device.stat().st_mode & 0o777 == 0o600
    print('PASS: built package, real daemon, TPM, UHID, udev ownership and existing-login activation', flush=True)
    # More failures than the old burst limit must recover without manual starts.
    for _ in range(4):
        before = pid('fidophir@1000.service')
        os.kill(int(before), signal.SIGKILL)
        wait(lambda: pid('fidophir@1000.service') != before and ready(1000))
    print('PASS: four consecutive crashes recover through the production restart policy', flush=True)
    run('systemctl', 'start', 'user@1001.service')
    wait(lambda: ready(1001))
    run('systemctl', 'stop', 'user@1001.service')
    wait(lambda: not active('fidophir@1001.service') and not Path('/dev/fidophir-1001').exists())
    assert Path('/var/lib/fidophir-users/1001').exists()
    print('PASS: second real user manager activates its own device; logout removes it and preserves state', flush=True)
    before = pid('fidophir@1000.service')
    run(*reinstall)
    wait(lambda: pid('fidophir@1000.service') != before and ready(1000))
    assert not active('fidophir@1001.service')
    before = pid('fidophir@1000.service')
    run('systemctl', 'restart', 'fidophir.target')
    wait(lambda: pid('fidophir@1000.service') != before and ready(1000))
    marker = state / 'lifecycle-test-marker'
    marker.write_text('preserve state')
    run(*remove)
    wait(lambda: not active('fidophir@1000.service') and not device.exists())
    assert marker.read_text() == 'preserve state'
    print('PASS: package reinstall, target restart and removal propagate; state survives removal', flush=True)
    if deb:
        policy = Path('/usr/sbin/policy-rc.d')
        policy.write_text('#!/bin/sh\nexit 101\n')
        policy.chmod(0o755)
    else:
        run('systemctl', 'mask', 'fidophir.target')
    run(*install)
    assert not active('fidophir.target') and not active('fidophir@1000.service')
    print('PASS: policy denial/masked target prevents existing-login activation', flush=True)
    run(*remove)


if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except Exception:
        for uid in (1000, 1001):
            device = Path(f'/dev/fidophir-{uid}')
            print(f'Device {device}: exists={device.exists()} symlink={device.is_symlink()}', flush=True)
            if device.exists():
                try:
                    subprocess.run(['runuser', '-u', f'key{uid}', '--', 'fido2-token', '-I', str(device)],
                                   timeout=5)
                except subprocess.TimeoutExpired:
                    print('GetInfo client timed out', flush=True)
        subprocess.run(['journalctl', '-b', '--no-pager', '-n', '200'])
        raise

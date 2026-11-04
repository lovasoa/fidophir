#!/usr/bin/python3
"""Exercise production unit dependencies and real package helpers in a disposable
booted container. The fixture worker replaces FIDO/TPM and sandboxing only;
the fixture disables restart-rate limits for rapid package transactions.
This checks packaging transactions, not hardware or service confinement.
Run as root inside Debian 13 (debhelper installed) or Fedora 44 (rpm-build).
"""
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()


def wait(predicate):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError('systemd lifecycle assertion timed out')


def active(unit):
    return subprocess.run(['systemctl', '--quiet', 'is-active', unit]).returncode == 0


def pid(unit):
    return run('systemctl', 'show', '-p', 'MainPID', '--value', unit)


def package(work, kind, version):
    source = work / version
    stage = source / 'debian/fidophir' if kind == 'deb' else source / 'stage'
    units = stage / 'usr/lib/systemd/system'
    units.mkdir(parents=True)
    for file in ('fidophir.target', 'fidophir@.service'):
        text = (ROOT / 'packaging' / file).read_text()
        if file.endswith('.service'):
            unit, install = text.split('[Service]')[0], text.split('[Install]')[1]
            unit = unit.replace('StartLimitIntervalSec=60', 'StartLimitIntervalSec=0')
            text = unit + '''[Service]
Type=exec
ExecStart=/usr/libexec/fidophir --user %i
User=fidophir
Group=fidophir
UMask=0077
StateDirectory=fidophir-users/%i
StateDirectoryMode=0700
[Install]''' + install
        (units / file).write_text(text)
    wants = units / 'user@.service.wants'
    wants.mkdir()
    (wants / 'fidophir@.service').symlink_to('../fidophir@.service')
    for src, dst in [('fidophir.sysusers', 'usr/lib/sysusers.d/fidophir.conf'),
                     ('00-fidophir.preset', 'usr/lib/systemd/system-preset/00-fidophir.preset'),
                     ('fidophir-package-setup', 'usr/libexec/fidophir-package-setup')]:
        dest = stage / dst
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / 'packaging' / src, dest)
    dummy = stage / 'usr/libexec/fidophir'
    dummy.write_text('#!/bin/sh\nprintf "%s\\n%s\\n" "$2" "$STATE_DIRECTORY" > "$STATE_DIRECTORY/instance"\nexec /bin/sleep infinity\n')
    dummy.chmod(0o755)
    if kind == 'deb':
        debian = source / 'debian'
        (debian / 'control').write_text('Source: fidophir\nMaintainer: Test <test@example.com>\nBuild-Depends: debhelper-compat (= 13)\n\nPackage: fidophir\nArchitecture: all\nDepends: ${misc:Depends}, systemd\nDescription: lifecycle test fixture\n')
        (debian / 'changelog').write_text(f'fidophir ({version}) unstable; urgency=low\n\n  * Test fixture.\n\n -- Test <test@example.com>  Wed, 04 Nov 2026 12:00:00 +0000\n')
        for name in ('postinst', 'postrm'):
            shutil.copy2(ROOT / 'debian' / name, debian / name)
        for command in (['dh_installsysusers'], ['dh_installsystemd', 'fidophir.target'], ['dh_installdeb'], ['dh_gencontrol'], ['dh_builddeb']):
            run(*command, cwd=source)
        return next(work.glob(f'fidophir_{version}_*.deb'))
    spec = source / 'fixture.spec'
    scriptlets = (ROOT / 'packaging/fidophir.spec').read_text().split('%post\n')[1].split('%files\n')[0]
    spec.write_text(f'''Name: fidophir
Version: {version}
Release: 1
Summary: lifecycle test fixture
License: Apache-2.0
BuildArch: noarch
%description
Lifecycle test fixture.
%install
mkdir -p %{{buildroot}}
cp -a {stage}/. %{{buildroot}}/
%post
{scriptlets}
%files
/usr/libexec/*
/usr/lib/systemd/system/*
/usr/lib/systemd/system-preset/*
/usr/lib/sysusers.d/*
''')
    run('rpmbuild', '-bb', '--define', f'_topdir {source}/rpmbuild', str(spec))
    return next(source.glob('rpmbuild/RPMS/noarch/*.rpm'))


def main(kind):
    assert os.geteuid() == 0 and Path('/run/systemd/container').exists(), 'use a disposable booted container'
    assert not Path('/usr/libexec/fidophir').exists() and not Path('/etc/fidophir').exists(), 'requires a clean test container'
    # Never restart a real desktop/user manager, even inside the test container.
    user = Path('/etc/systemd/system/user@.service')
    user.write_text('[Service]\nType=exec\nExecStart=/bin/sleep infinity\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'user@1000.service')
    Path('/usr/sbin/policy-rc.d').unlink(missing_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        first, second = package(work, kind, '1.0'), package(work, kind, '2.0')
        install = ['dpkg', '-i'] if kind == 'deb' else ['rpm', '-Uvh']
        run(*install, str(first))
        wait(lambda: active('fidophir@1000.service'))
        owner = pwd.getpwnam('fidophir').pw_uid
        state = Path('/var/lib/fidophir-users/1000')
        wait(lambda: (state / 'instance').exists())
        assert state.stat().st_uid == owner and state.stat().st_mode & 0o777 == 0o700
        assert (state / 'instance').read_text().splitlines() == ['1000', str(state)]
        print(f'PASS {kind}: automatic account/directory creation and existing-login activation', flush=True)
        run('systemctl', 'start', 'user@1001.service')
        wait(lambda: active('fidophir@1001.service'))
        run('systemctl', 'stop', 'user@1001.service')
        wait(lambda: not active('fidophir@1001.service'))
        assert Path('/var/lib/fidophir-users/1001').exists()
        print(f'PASS {kind}: template UID propagation, logout stop and state retention', flush=True)
        before = pid('fidophir@1000.service')
        run(*install, str(second))
        wait(lambda: active('fidophir@1000.service') and pid('fidophir@1000.service') != before)
        assert not active('fidophir@1001.service')
        print(f'PASS {kind}: helper-driven target upgrade restarts only running instances', flush=True)
        before = pid('fidophir@1000.service')
        run('systemctl', 'restart', 'fidophir.target')
        wait(lambda: active('fidophir@1000.service') and pid('fidophir@1000.service') != before)
        legacy = Path('/var/lib/fidophir')
        (legacy / 'v1').mkdir(parents=True, exist_ok=True)
        (legacy / 'v1/credential-fixture').write_text('preserve this credential')
        owner_config = Path('/etc/fidophir')
        owner_config.mkdir(exist_ok=True)
        (owner_config / 'owner.conf').write_text('FIDOPHIR_OWNER_UID=1000\n')
        third = package(work, kind, '3.0')
        run(*install, str(third))
        wait(lambda: (legacy / 'instance').exists())
        assert (legacy / 'instance').read_text().splitlines() == ['1000', str(legacy)]
        assert (legacy / 'v1/credential-fixture').read_text() == 'preserve this credential'
        print(f'PASS {kind}: package override preserves legacy state and supplies STATE_DIRECTORY', flush=True)
        remove = ['dpkg', '--remove', 'fidophir'] if kind == 'deb' else ['rpm', '-e', 'fidophir']
        run(*remove)
        wait(lambda: not active('fidophir@1000.service'))
        assert state.exists() and (legacy / 'v1/credential-fixture').exists()
        print(f'PASS {kind}: target restart/removal propagation and state retention', flush=True)
        if kind == 'deb':
            policy = Path('/usr/sbin/policy-rc.d')
            policy.write_text('#!/bin/sh\nexit 101\n')
            policy.chmod(0o755)
        else:
            run('systemctl', 'mask', 'fidophir.target')
        run(*install, str(third))
        assert not active('fidophir.target') and not active('fidophir@1000.service')
        print(f'PASS {kind}: policy denial/masked target prevents existing-login activation', flush=True)
        run(*remove)



if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except subprocess.CalledProcessError as error:
        print(error.output)
        raise

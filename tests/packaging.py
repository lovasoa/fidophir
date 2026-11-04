#!/usr/bin/python3
"""Test installation-only activation and legacy configuration without host writes.
Real package-manager/systemd lifecycle checks live in systemd_lifecycle.py.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MOCK = '''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
name, args = Path(sys.argv[0]).name, sys.argv[1:]
with open(os.environ['CALLS'], 'a') as f:
    f.write(json.dumps([name, *args]) + '\\n')
if name == 'systemctl' and 'list-units' in args:
    for uid in ('1000', '1001', '0', 'invalid'):
        print(f'user@{uid}.service loaded active running User manager')
if name == 'systemctl' and 'is-active' in args:
    sys.exit(3 if os.environ.get('TARGET_STOPPED') else 0)
if name == 'systemctl' and args == ['start', 'fidophir@1000.service'] and os.environ.get('START_FAIL'):
    sys.exit(1)
if name == 'policy-rc.d' and os.environ.get('POLICY_DENY'):
    sys.exit(101)
'''


class Installation(unittest.TestCase):
    def invoke(self, phase='activate', live=True, legacy=None, override=None, expected=0, stderr_contains=None, **settings):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            tools, config, units = folder / 'bin', folder / 'owner', folder / 'units'
            tools.mkdir()
            config.mkdir()
            if legacy is not None:
                (config / 'owner.conf').write_text(legacy)
            if override is not None:
                target = units / 'fidophir@1000.service.d'
                target.mkdir(parents=True)
                (target / 'owner-state.conf').write_text(override)
            calls = folder / 'calls'
            calls.touch()
            for name in ('systemctl', 'deb-systemd-invoke', 'modprobe', 'udevadm', 'policy-rc.d'):
                path = tools / name
                path.write_text(MOCK)
                path.chmod(0o755)
            script = folder / 'script'
            text = (ROOT / 'packaging/fidophir-package-setup').read_text()
            for old, new in [('/run/systemd/system', folder if live else folder / 'missing'), ('/etc/fidophir', config), ('/etc/systemd/system', units), ('/usr/sbin/policy-rc.d', tools / 'policy-rc.d')]:
                text = text.replace(old, str(new))
            script.write_text(text)
            env = dict(os.environ, PATH=f'{tools}:/usr/bin:/bin', CALLS=str(calls), **settings)
            result = subprocess.run(['sh', str(script), phase, 'deb-systemd-invoke'], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stderr)
            if stderr_contains is not None:
                self.assertIn(stderr_contains, result.stderr)
            files = {str(p.relative_to(units)): p.read_text() for p in units.rglob('*.conf')}
            return [json.loads(line) for line in calls.read_text().splitlines()], files

    def test_existing_logins_start_without_restart_or_account_changes(self):
        calls, _ = self.invoke()
        self.assertEqual([c for c in calls if c[:2] == ['systemctl', 'start']], [['systemctl', 'start', f'fidophir@{uid}.service'] for uid in (1000, 1001)])
        self.assertLess(calls.index(['udevadm', 'trigger', '--settle', '--action=change', '--subsystem-match=misc', '--sysname-match=uhid']), calls.index(['systemctl', 'start', 'fidophir@1000.service']))

    def test_debian_policy_denial_prevents_dependency_activation(self):
        calls, _ = self.invoke(POLICY_DENY='yes')
        self.assertFalse(any(c[0] == 'systemctl' and 'start' in c for c in calls))

    def test_stopped_target_prevents_activation(self):
        calls, _ = self.invoke(TARGET_STOPPED='yes')
        self.assertFalse(any('start' in c for c in calls))

    def test_start_failure_is_reported_and_other_users_are_started(self):
        calls, _ = self.invoke(START_FAIL='yes', stderr_contains='failed to start fidophir@1000.service')
        self.assertIn(['systemctl', 'start', 'fidophir@1001.service'], calls)

    def test_chroot_does_not_touch_host(self):
        calls, _ = self.invoke(live=False)
        self.assertEqual(calls, [])

    def test_legacy_state_selected_by_unit_override(self):
        for value in ('1000', '"1000"', "'1000'"):
            _, files = self.invoke('prepare', live=False, legacy=f'FIDOPHIR_OWNER_UID={value}\nFIDOPHIR_OWNER_SEAT=seat0\n')
            self.assertEqual(files, {'fidophir@1000.service.d/owner-state.conf': '[Service]\nStateDirectory=\nStateDirectory=fidophir\n'})

    def test_existing_administrator_override_is_preserved(self):
        _, files = self.invoke('prepare', live=False, legacy='FIDOPHIR_OWNER_UID=1000\n', override='# administrator configuration\n')
        self.assertEqual(files['fidophir@1000.service.d/owner-state.conf'], '# administrator configuration\n')

    def test_malformed_legacy_configuration_is_not_executed_or_reassigned(self):
        for value in ('0', '1000\nFIDOPHIR_OWNER_UID=1001', '$(exit 0)', '1000; true'):
            _, files = self.invoke('prepare', live=False, legacy=f'FIDOPHIR_OWNER_UID={value}\n', expected=1)
            self.assertEqual(files, {})


if __name__ == '__main__':
    unittest.main()

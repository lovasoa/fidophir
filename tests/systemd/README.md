# Package lifecycle tests

Run these tests in a disposable VM with Docker, sudo, and the UHID kernel module available.
Build the RPM test variant on Fedora with the [package build dependencies](../../packaging/README.md#build-packages):

```sh
CARGO_FEATURES=systemd-tests RPM_BINARY_ONLY=1 ./packaging/build.sh rpm systemd-packages
```

Copy the binary RPM into `systemd-packages/` in a checkout on the test VM, then run:

```sh
bash tests/systemd_container.sh rpm
```

For DEB, build with `CARGO_FEATURES=systemd-tests ./packaging/build.sh deb systemd-packages`, copy the DEB instead, and use `deb` in the test command. Keep exactly one test package in `systemd-packages/`.

The package workflow runs the same helper on a fresh GitHub-hosted Ubuntu VM. The helper builds a runtime image from the matching pinned
package builder base and boots systemd as PID 1. It needs Docker, sudo, and the
UHID kernel module. Docker's private `/dev` does not receive new devtmpfs
nodes, so the test creates the matching character node from its real sysfs
major/minor and retriggers the actual installed udev rules. Privileged execution
and writable sysfs/cgroups are confined
to that disposable runner.

The package is built through the regular DEB/RPM recipes with the
`systemd-tests` Cargo feature. That feature changes only the TPM transport to
the real tpm2-abrmd system-bus resource manager, backed by swtpm outside the
service's private network. Production packages still use `/dev/tpmrm0` and are
published separately. This avoids depending on the runner kernel's optional
vTPM proxy module and preserves every production service sandbox setting.

The test installs that package with its native package manager. Real systemd
user managers activate the real daemon, whose CTAP GetInfo is queried through
UHID/hidraw as each device's intended user. It checks installed udev ownership,
state permissions, repeated crash recovery, logout, package reinstall, target
restart, removal with state retention, and policy-denied installation. A PIN
setup request without a graphical session must fail closed.

This does not verify successful desktop authentication, a physical TPM, or an
upgrade between distinct released versions. The desktop adapter integration
suite covers approval decisions; physical acceptance remains separate. On
failure, both the Python test and container helper print the system journal.

#!/usr/bin/env bash
# Test the installation hook without accessing the host's services.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
mkdir "$test_dir/bin" "$test_dir/live"
export CALLS="$test_dir/calls"
export PATH="$test_dir/bin:/usr/bin:/bin"

cat >"$test_dir/bin/mock" <<'MOCK'
#!/usr/bin/env bash
set -eu
name=${0##*/}
printf '%s' "$name" >>"$CALLS"
printf ' %s' "$@" >>"$CALLS"
printf '\n' >>"$CALLS"
if [[ $name == systemctl && " $* " == *' list-units '* ]]; then
    for uid in 1000 1001 0 invalid; do
        echo "user@$uid.service loaded active running User manager"
    done
fi
if [[ $name == systemctl && " $* " == *' is-active '* && -n ${TARGET_STOPPED:-} ]]; then exit 3; fi
if [[ $name == systemctl && "$*" == 'start fidophir@1000.service' && -n ${START_FAIL:-} ]]; then exit 1; fi
if [[ $name == policy-rc.d && -n ${POLICY_DENY:-} ]]; then exit 101; fi
MOCK
chmod +x "$test_dir/bin/mock"
for name in systemctl deb-systemd-invoke modprobe udevadm policy-rc.d; do
    ln -s mock "$test_dir/bin/$name"
done

run_hook() {
    local systemd_dir=$1
    : >"$CALLS"
    sed -e "s|/run/systemd/system|$systemd_dir|g" \
        -e "s|/usr/sbin/policy-rc.d|$test_dir/bin/policy-rc.d|g" \
        "$repo/packaging/fidophir-package-setup" >"$test_dir/hook"
    sh "$test_dir/hook" deb-systemd-invoke 2>"$test_dir/stderr"
}

run_hook "$test_dir/live"
grep -qx 'systemctl start fidophir@1000.service' "$CALLS"
grep -qx 'systemctl start fidophir@1001.service' "$CALLS"
[[ $(grep -c '^systemctl start ' "$CALLS") == 2 ]]
trigger=$(grep -n '^udevadm trigger ' "$CALLS" | cut -d: -f1)
start=$(grep -n '^systemctl start fidophir@1000.service' "$CALLS" | cut -d: -f1)
(( trigger < start ))

POLICY_DENY=yes run_hook "$test_dir/live"
! grep -q '^systemctl start ' "$CALLS"
TARGET_STOPPED=yes run_hook "$test_dir/live"
! grep -q '^systemctl start ' "$CALLS"
START_FAIL=yes run_hook "$test_dir/live"
grep -q 'failed to start fidophir@1000.service' "$test_dir/stderr"
grep -qx 'systemctl start fidophir@1001.service' "$CALLS"
run_hook "$test_dir/missing"
[[ ! -s $CALLS ]]
echo 'PASS: package activation policy and failure handling'

#!/usr/bin/env bash
# Run only on a disposable runner: privileged containers share the host kernel.
set -euo pipefail
kind=${1:?usage: systemd_container.sh deb|rpm}
repo=$(cd "$(dirname "$0")/.." && pwd)
case "$kind" in
    deb) base=$(awk '$1 == "FROM" {print $2}' "$repo/packaging/images/deb/Dockerfile") ;;
    rpm) base=$(awk '$1 == "FROM" {print $2}' "$repo/packaging/images/rpm/Dockerfile") ;;
    *) exit 2 ;;
esac
sudo modprobe uhid
test -c /dev/uhid
image="fidophir-systemd-$kind"
container="fidophir-systemd-$kind"
cleanup() {
    docker exec "$container" journalctl --no-pager -b --no-hostname -t systemd -t fidophir -t tpm2-abrmd -t swtpm > "$repo/systemd-$kind.log" 2>&1 || true
    docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker build --build-arg "BASE=$base" --build-arg "KIND=$kind" \
    -t "$image" -f "$repo/tests/systemd/Dockerfile" "$repo/tests/systemd"
# Host networking lets udev receive host-kernel device uevents. The daemon
# still receives its own PrivateNetwork=yes namespace from the shipped unit.
docker run -d --name "$container" --privileged --cgroupns=host --network=host \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    -v /sys:/sys:rw -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$repo:/repo:ro" -v "$repo/systemd-packages:/packages:ro" \
    --device /dev/uhid "$image" /sbin/init
for attempt in {1..60}; do
    if docker exec "$container" systemctl is-active --quiet dbus.service; then break; fi
    sleep 1
done
docker exec "$container" bash /repo/tests/systemd/setup.sh
shopt -s nullglob
packages=("$repo"/systemd-packages/*."$kind")
[[ ${#packages[@]} == 1 ]] || { echo 'Expected one test package' >&2; exit 1; }
docker exec "$container" python3 /repo/tests/systemd_lifecycle.py "/packages/${packages[0]##*/}"

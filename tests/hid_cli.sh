#!/usr/bin/env bash
# Exercise the real FIDO command-line tools against a disposable UHID device.
set -euo pipefail

binary=$(realpath "${1:?integration binary required}")
test_dir=$(mktemp -d)
port=$((20000 + $$ % 20000))
tcti="swtpm:host=127.0.0.1,port=$port"
simulator_pid=
authenticator_pid=
device=

cleanup() {
    for pid in "$authenticator_pid" "$simulator_pid"; do
        if [[ -n $pid ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf -- "$test_dir"
}
trap cleanup EXIT

find_test_device() {
    local entry found=
    for entry in /sys/class/hidraw/hidraw*; do
        [[ -f $entry/device/uevent ]] || continue
        if grep -qx 'HID_PHYS=fidophir-v2' "$entry/device/uevent" &&
           grep -qx 'HID_UNIQ=4294967295' "$entry/device/uevent"; then
            if [[ -n $found ]]; then
                echo 'Multiple Fidophir test devices found' >&2
                return 1
            fi
            found="/dev/${entry##*/}"
        fi
    done
    printf '%s' "$found"
}

chmod 700 "$test_dir"
mkdir -m 700 "$test_dir/tpm" "$test_dir/state"
export TSS2_LOG=all+NONE

swtpm socket --tpm2 --tpmstate "dir=$test_dir/tpm" \
    --server "type=tcp,port=$port,bindaddr=127.0.0.1" \
    --ctrl "type=tcp,port=$((port + 1)),bindaddr=127.0.0.1" \
    --flags not-need-init,startup-clear >"$test_dir/swtpm.log" 2>&1 &
simulator_pid=$!
sleep 0.5
if ! kill -0 "$simulator_pid" 2>/dev/null; then
    cat "$test_dir/swtpm.log" >&2
    exit 1
fi

"$binary" "$test_dir/state" "$tcti" uhid >"$test_dir/device.log" 2>&1 &
authenticator_pid=$!
# Device creation and udev permissions are asynchronous.
for _ in {1..100}; do
    if ! kill -0 "$authenticator_pid" 2>/dev/null; then
        cat "$test_dir/device.log" >&2
        exit 1
    fi
    device=$(find_test_device)
    if [[ -n $device && -r $device && -w $device && -L /dev/fidophir-4294967295 ]] &&
       [[ $(readlink -f /dev/fidophir-4294967295) == "$device" ]]; then
        break
    fi
    sleep 0.1
done
if [[ -z $device || ! -r $device || ! -w $device || ! -L /dev/fidophir-4294967295 ]] ||
   [[ $(readlink -f /dev/fidophir-4294967295) != "$device" ]]; then
    echo 'Fidophir test device was not available or accessible' >&2
    cat "$test_dir/device.log" >&2
    for entry in /sys/class/hidraw/hidraw*; do
        [[ -f $entry/device/uevent ]] || continue
        cat "$entry/device/uevent" >&2
        ls -l "/dev/${entry##*/}" >&2 || true
        udevadm info -q property -n "/dev/${entry##*/}" >&2 || true
    done
    ls -l /dev/fidophir-* >&2 || true
    exit 1
fi
device=/dev/fidophir-4294967295

# A detached session makes the tools read the synthetic PINs from stdin.
printf '1234\n1234\n' | setsid fido2-token -S "$device"
cat >"$test_dir/credential-input" <<'PARAMETERS'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
example.test
test
dGVzdA==
PARAMETERS
printf '1234\n' | setsid fido2-cred -M -r -v \
    -i "$test_dir/credential-input" -o "$test_dir/credential-output" "$device"
printf '1234\n8765\n8765\n' | setsid fido2-token -C "$device"
printf '8765\n' | setsid fido2-token -L -r "$device" >"$test_dir/rps"
grep -q 'example\.test' "$test_dir/rps"
printf '8765\n' | setsid fido2-token -L -k example.test "$device" >"$test_dir/credentials"
credential_id=$(awk 'NR == 1 {print $2}' "$test_dir/credentials")
[[ -n $credential_id && $(wc -l <"$test_dir/credentials") == 1 ]]
printf '8765\n' | setsid fido2-token -D -i "$credential_id" "$device"
printf '8765\n' | setsid fido2-token -I -c "$device" >"$test_dir/metadata"
grep -q 'existing rk\(s\): 0' "$test_dir/metadata"
echo 'PASS: FIDO CLI PIN and credential management through UHID and hidraw'

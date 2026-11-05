#!/usr/bin/python3
"""Independent python-fido2 client against the test-only Rust pipe transport.

All accounts/keys are synthetic. Only a disposable loopback swtpm is used.
This does not validate Linux UHID, GNOME or real website compatibility.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time

from fido2.ctap import CtapDevice, CtapError
from fido2.hid import CAPABILITY, CTAPHID
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.ctap2.credman import CredentialManagement
from fido2 import cbor


class Pipe(CtapDevice):
    def __init__(self, binary, root, tcti, decision="allow", capture_stderr=False):
        self.proc = subprocess.Popen([str(binary), str(root), tcti, decision],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE if capture_stderr else None)

    @property
    def capabilities(self):
        return CAPABILITY.CBOR

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == CTAPHID.CBOR
        self.proc.stdin.write(struct.pack(">I", len(data)) + data)
        self.proc.stdin.flush()

        def read_exact(length):
            value = b""
            while len(value) < length:
                piece = self.proc.stdout.read(length - len(value))
                if not piece:
                    raise RuntimeError(f"Rust test bridge exited: {self.proc.poll()}")
                value += piece
            return value

        length = struct.unpack(">I", read_exact(4))[0]
        assert 1 <= length <= 7609
        return read_exact(length)

    @classmethod
    def list_devices(cls):
        return iter(())

    def close(self, expected=0):
        if self.proc.stdin:
            self.proc.stdin.close()
        assert self.proc.wait(timeout=15) == expected
        self.proc.stdout.close()


def expect_fail_stop(pipe, operation):
    """An infallible OpenSK crypto callback must stop rather than fabricate output."""
    try:
        operation()
    except RuntimeError as error:
        assert "Rust test bridge exited" in str(error), error
    else:
        raise AssertionError("hardware failure emitted a protocol response instead of stopping")
    pipe.close(expected=1)
    diagnostics = pipe.proc.stderr.read().decode()
    pipe.proc.stderr.close()
    assert "fatal" in diagnostics and "sign" in diagnostics, diagnostics
    return diagnostics


def expect(code, fn):
    try:
        fn()
    except CtapError as error:
        assert error.code == code, f"expected {code}, got {error.code}"
    else:
        raise AssertionError(f"expected {code}")


def authorize(ctap, pin, permission, rp=None):
    client = ClientPin(ctap)
    token = client.get_pin_token(pin, permission, rp)
    return client.protocol, token


def register(ctap, pin, user, rp="example.test"):
    digest = os.urandom(32)
    protocol, token = authorize(ctap, pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp)
    response = ctap.make_credential(digest, {"id": rp, "name": "Synthetic test"},
        {"id": user, "name": "test", "displayName": "Test account"},
        [{"type": "public-key", "alg": -7}], options={"rk": True},
        extensions={"hmac-secret": True, "credProtect": 3},
        pin_uv_param=protocol.authenticate(token, digest), pin_uv_protocol=protocol.VERSION)
    assert response.auth_data.is_user_present() and response.auth_data.is_user_verified()
    assert response.auth_data.counter == 0
    credential = response.auth_data.credential_data
    credential.public_key.verify(bytes(response.auth_data) + digest, response.att_stmt["sig"])
    return credential


def sign(ctap, pin, credential, rp="example.test"):
    digest = os.urandom(32)
    protocol, token = authorize(ctap, pin, ClientPin.PERMISSION.GET_ASSERTION, rp)
    response = ctap.get_assertion(rp, digest,
        [{"id": credential.credential_id, "type": "public-key"}],
        pin_uv_param=protocol.authenticate(token, digest), pin_uv_protocol=protocol.VERSION)
    assert response.auth_data.is_user_present() and response.auth_data.is_user_verified()
    assert response.auth_data.counter == 0
    credential.public_key.verify(bytes(response.auth_data) + digest, response.signature)


def free_ports():
    for _ in range(100):
        with socket.socket() as a:
            a.bind(("127.0.0.1", 0))
            port = a.getsockname()[1]
            if port == 65535:
                continue
            try:
                with socket.socket() as b:
                    b.bind(("127.0.0.1", port + 1))
                return port
            except OSError:
                continue
    raise RuntimeError("no simulator port pair")


def tpm_dictionary_attack_counter(tcti):
    properties = subprocess.check_output(
        ["tpm2_getcap", "-T", tcti, "properties-variable"], text=True)
    counter = re.search(r"TPM2_PT_LOCKOUT_COUNTER:\s*(0x[0-9a-fA-F]+|\d+)", properties)
    assert counter, "simulator did not report its dictionary-attack counter"
    return int(counter[1], 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expiry", action="store_true", help="also wait 31s to check real token expiry")
    parser.add_argument("--capacity", action="store_true", help="exercise a full credential store")
    args = parser.parse_args()
    os.environ["TSS2_LOG"] = "all+NONE"
    with tempfile.TemporaryDirectory(prefix="fidophir-interop-") as directory:
        base = Path(directory)
        simulator, state = base / "simulator", base / "records"
        simulator.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        port = free_ports()
        tcti = f"swtpm:host=127.0.0.1,port={port}"
        with (base / "simulator.log").open("wb") as log:
            sim = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={simulator}",
                "--server", f"type=tcp,port={port},bindaddr=127.0.0.1",
                "--ctrl", f"type=tcp,port={port+1},bindaddr=127.0.0.1",
                "--flags", "not-need-init,startup-clear"], stdout=log, stderr=log)
            pipe = None
            try:
                time.sleep(0.3)
                assert sim.poll() is None, "simulator did not start"
                # Private simulator only: keep hardware DA below lockout while testing
                # OpenSK's independent persistent eight-attempt limit across restarts.
                subprocess.run(["tpm2_dictionarylockout","-T",tcti,"--setup-parameters",
                                "--max-tries","64","--recovery-time","1000","--lockout-recovery-time","1000"],check=True)
                pipe = Pipe(args.binary, state, tcti)
                ctap = Ctap2(pipe)
                info = ctap.get_info()
                assert info.options["rk"] and info.options["alwaysUv"]
                assert info.pin_uv_protocols == [2]
                assert not info.options["clientPin"]
                assert info.min_pin_length == 4
                pin, new_pin = "1234", "8765"
                ClientPin(ctap).set_pin(pin)
                assert ctap.get_info().options["clientPin"]
                print("PASS: native ClientPIN v2 setup", flush=True)

                expect(CtapError.ERR.PIN_INVALID, lambda: authorize(ctap, "wrongpin", ClientPin.PERMISSION.MAKE_CREDENTIAL, "example.test"))
                assert tpm_dictionary_attack_counter(tcti) >= 1, "wrong PIN did not reach TPM DA protection"
                print("PASS: incorrect PIN rejected by hardware authorization; DA counter increased", flush=True)

                # The public configured-PIN marker is all zeroes; submitting it
                # must still reach TPM authorization and consume a hardware retry.
                client = ClientPin(ctap)
                agreement, secret = client._get_shared_secret()
                expect(CtapError.ERR.PIN_INVALID,lambda:ctap.client_pin(
                    client.protocol.VERSION,ClientPin.CMD.GET_TOKEN_USING_PIN,
                    key_agreement=agreement,pin_hash_enc=client.protocol.encrypt(secret,bytes(16)),
                    permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,permissions_rpid="example.test"))
                assert tpm_dictionary_attack_counter(tcti) >= 2, "configured-PIN marker bypassed TPM verification"
                print("PASS: configured-PIN marker cannot authorize; zero candidate is rejected by TPM",flush=True)

                first = register(ctap,pin,b"first-account")
                second = register(ctap,pin,b"second-account")
                sign(ctap,pin,first)
                sign(ctap,pin,second)
                # Only a genuine sixteen-byte candidate may reach the TPM. The
                # adapter must leave OpenSK's ordinary mismatch path intact for
                # invalid ciphertext and valid ciphertext of the wrong length.
                hardware_attempts = tpm_dictionary_attack_counter(tcti)
                for shape in ("empty", "partial-block", "long-plaintext"):
                    client = ClientPin(ctap)
                    agreement, secret = client._get_shared_secret()
                    encrypted = {"empty": b"", "partial-block": b"x",
                                 "long-plaintext": client.protocol.encrypt(secret, bytes(32))}[shape]
                    retries = client.get_pin_retries()[0]
                    expect(CtapError.ERR.PIN_INVALID, lambda: ctap.client_pin(
                        client.protocol.VERSION, ClientPin.CMD.GET_TOKEN_USING_PIN,
                        key_agreement=agreement, pin_hash_enc=encrypted,
                        permissions=ClientPin.PERMISSION.GET_ASSERTION,
                        permissions_rpid="example.test"))
                    assert client.get_pin_retries()[0] == retries - 1
                    sign(ctap, pin, first)  # Fresh request cannot reuse captured key/candidate.
                assert tpm_dictionary_attack_counter(tcti) == hardware_attempts
                print("PASS: malformed PIN ciphertext consumes retries and cannot poison the next request", flush=True)
                if args.capacity:
                    pipe.close(); pipe = None
                    records = state / "v2" / "credentials"
                    # Synthetic records reuse a test key but have distinct IDs and users.
                    for slot in range(2, 299):
                        path = records / f"{slot:05d}"
                        shutil.copytree(records / "00000", path)
                        (path / "credential-id.bin").write_bytes(slot.to_bytes(32, "big"))
                        (path / "user-handle.bin").write_bytes(slot.to_bytes(4, "big"))
                    pipe = Pipe(args.binary, state, tcti)
                    ctap = Ctap2(pipe)
                    sign(ctap, pin, first)
                    last = register(ctap, pin, b"capacity-last")
                    sign(ctap, pin, last)
                    expect(CtapError.ERR.KEY_STORE_FULL, lambda: register(ctap, pin, b"capacity-overflow"))
                    pipe.close(); pipe = None
                    for slot in range(2, 300):
                        shutil.rmtree(records / f"{slot:05d}")
                    pipe = Pipe(args.binary, state, tcti)
                    ctap = Ctap2(pipe)
                    print("PASS: 300 credentials, full-store rejection and existing credential after restart", flush=True)
                assert not (state / "v2/authenticator/pin-properties.bin").exists(), "software PIN verifier was written"
                h = hashlib.sha256(pin.encode()).digest()[:16]
                assert all(h not in f.read_bytes() for f in (state / "v2").rglob("*") if f.is_file())
                print("PASS: two TPM-backed credentials, self-attestation and independent signature verification", flush=True)

                expect(CtapError.ERR.UNSUPPORTED_OPTION, lambda: ctap.make_credential(os.urandom(32),
                    {"id":"example.test"},{"id":b"nonresident"},[{"type":"public-key","alg":-7}],options={"rk":False}))
                digest = os.urandom(32)
                protocol, token = authorize(ctap,pin,ClientPin.PERMISSION.MAKE_CREDENTIAL,"example.test")
                expect(CtapError.ERR.PIN_AUTH_INVALID, lambda: ctap.make_credential(digest,
                    {"id":"other.test"},{"id":b"wrong-rp"},[{"type":"public-key","alg":-7}],options={"rk":True},
                    pin_uv_param=protocol.authenticate(token,digest),pin_uv_protocol=2))
                print("PASS: resident-only profile and token RP binding", flush=True)

                if args.expiry:
                    protocol, token = authorize(ctap,pin,ClientPin.PERMISSION.GET_ASSERTION,"example.test")
                    print("Checking 30-second token expiry…",flush=True)
                    time.sleep(31)
                    digest = os.urandom(32)
                    expect(CtapError.ERR.PIN_AUTH_INVALID,lambda:ctap.get_assertion("example.test",digest,
                        [{"id":first.credential_id,"type":"public-key"}],
                        pin_uv_param=protocol.authenticate(token,digest),pin_uv_protocol=2))
                    sign(ctap,pin,first)
                    print("PASS: expired token rejected; new PIN authorization works",flush=True)

                old_parent = (state / "v2/authenticator/tpm-parent.bin").read_bytes()
                before = {str(f.relative_to(state)): f.read_bytes() for f in (state / "v2/credentials").rglob("*") if f.is_file()}
                # Exercise the existing forced-change comparison through KeyStore:
                # it may compare only the candidate just verified by TPM, not the marker.
                force = state / "v2/authenticator/force-pin-change.flag"
                os.close(os.open(force,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600))
                expect(CtapError.ERR.PIN_POLICY_VIOLATION,lambda:ClientPin(ctap).change_pin(pin,pin))
                assert force.exists()
                ClientPin(ctap).change_pin(pin,new_pin)
                assert not force.exists(), "successful PIN change did not clear forced-change state"
                assert before == {str(f.relative_to(state)): f.read_bytes() for f in (state / "v2/credentials").rglob("*") if f.is_file()}
                sign(ctap,new_pin,first)
                protocol, token = authorize(ctap, new_pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
                pipe.close(); pipe = None
                pipe = Pipe(args.binary,state,tcti)
                ctap = Ctap2(pipe)
                expect(CtapError.ERR.PIN_AUTH_INVALID,
                       lambda: CredentialManagement(ctap, protocol, token).get_metadata())
                expect(CtapError.ERR.PIN_INVALID,lambda:authorize(ctap,pin,ClientPin.PERMISSION.GET_ASSERTION,"example.test"))
                sign(ctap,new_pin,first)
                print("PASS: PIN change preserves credential blobs and survives process restart",flush=True)

                protocol,token = authorize(ctap,new_pin,ClientPin.PERMISSION.CREDENTIAL_MGMT)
                manager = CredentialManagement(ctap,protocol,token)
                rps = manager.enumerate_rps()
                assert len(rps) == 1
                credentials = manager.enumerate_creds(rps[0][CredentialManagement.RESULT.RP_ID_HASH])
                assert len(credentials) == 2
                print("PASS: standard credential-management enumeration",flush=True)

                # Unpatched OpenSK retains its old token after a failed PIN
                # attempt. Clearing only the TPM grant would leave metadata
                # operations usable: they do not sign or load a TPM key.
                expect(CtapError.ERR.PIN_INVALID, lambda: authorize(
                    ctap, "wrongpin", ClientPin.PERMISSION.CREDENTIAL_MGMT))
                expect(CtapError.ERR.PIN_AUTH_INVALID, manager.get_metadata)
                expect(CtapError.ERR.PIN_AUTH_INVALID, lambda: manager.delete_cred(
                    {"id": first.credential_id, "type": "public-key"}))
                sign(ctap, new_pin, first)
                print("PASS: revoked host authorization blocks stale-token metadata reads and deletion", flush=True)

                disposable = register(ctap, new_pin, b"delete-me")
                protocol, token = authorize(ctap, new_pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
                manager = CredentialManagement(ctap, protocol, token)
                manager.delete_cred({"id": disposable.credential_id, "type": "public-key"})
                expect(CtapError.ERR.NO_CREDENTIALS, lambda: sign(ctap, new_pin, disposable))
                sign(ctap, new_pin, first)
                print("PASS: credential-management deletion preserves other credentials", flush=True)

                directory = next(f.parent for f in (state / "v2/credentials").glob("*/credential-id.bin")
                                 if f.read_bytes() == first.credential_id)
                metadata = directory / "metadata.ini"
                original_metadata = metadata.read_bytes()
                remaining = ctap.get_info().remaining_disc_creds
                metadata.chmod(0o644)
                expect(0xF3, ctap.get_info)
                assert directory.is_dir()
                metadata.chmod(0o600)
                metadata.write_text("[broken INI")
                assert ctap.get_info().remaining_disc_creds == remaining + 1
                parked = directory.with_name(directory.name + ".damaged-1")
                assert parked.is_dir() and not directory.exists()
                expect(CtapError.ERR.NO_CREDENTIALS, lambda: sign(ctap, new_pin, first))
                sign(ctap, new_pin, second)
                replacement = register(ctap, new_pin, b"parked-slot-reuse")
                assert directory.is_dir() and parked.is_dir()
                assert ctap.get_info().remaining_disc_creds == remaining
                protocol, token = authorize(ctap, new_pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
                manager = CredentialManagement(ctap, protocol, token)
                assert manager.get_metadata()[CredentialManagement.RESULT.MAX_REMAINING_COUNT] == remaining
                manager.delete_cred({"id": replacement.credential_id, "type": "public-key"})
                pipe.close(); pipe = None
                (parked / "metadata.ini").write_bytes(original_metadata)
                parked.rename(directory)
                pipe = Pipe(args.binary, state, tcti)
                ctap = Ctap2(pipe)
                assert ctap.get_info().remaining_disc_creds == remaining
                sign(ctap, new_pin, first)
                print("PASS: damaged credential parked, slot reused, and credential restored", flush=True)

                pipe.close(); pipe = None
                removed = base / "removed-credential"
                shutil.move(directory, removed)
                pipe = Pipe(args.binary, state, tcti)
                ctap = Ctap2(pipe)
                expect(CtapError.ERR.NO_CREDENTIALS, lambda: sign(ctap, new_pin, first))
                sign(ctap, new_pin, second)
                shutil.move(removed, directory)
                sign(ctap, new_pin, first)
                print("PASS: admin deletion survives restart; directory restore works", flush=True)

                # OpenSK's signing interface cannot report hardware failure.
                # A structurally valid but damaged TPM key must therefore stop
                # the process, with no fabricated response, and recover on restart.
                pipe.close(); pipe = None
                pipe = Pipe(args.binary, state, tcti, capture_stderr=True)
                ctap = Ctap2(pipe)
                record_file = directory / "tpm-signing-blob.bin"
                original = record_file.read_bytes()
                wrapped = cbor.decode(original)
                damaged = bytearray(wrapped[2]); damaged[-1] ^= 1; wrapped[2] = bytes(damaged)
                record_file.write_bytes(cbor.encode(wrapped))
                diagnostics = expect_fail_stop(pipe, lambda: sign(ctap, new_pin, first))
                pipe = None
                assert new_pin not in diagnostics and "example.test" not in diagnostics
                # This private simulator uses raw TCP, without the kernel TPM
                # resource manager used by production /dev/tpmrm0. Emulate its
                # close-time object cleanup after the intentional abrupt exit.
                # Never do this against a physical/shared TPM.
                subprocess.run(["tpm2_flushcontext", "-T", tcti, "-t"], check=True)
                pipe = Pipe(args.binary, state, tcti)
                ctap = Ctap2(pipe)
                sign(ctap, new_pin, second)
                record_file.write_bytes(original)
                sign(ctap, new_pin, first)
                print("PASS: signing hardware failure stops safely; restart restores healthy and repaired credentials", flush=True)

                # Simulate missing shared state while running. Never silently
                # provision a new parent that would orphan the remaining keys.
                parent_file = state / "v2/authenticator/tpm-parent.bin"
                current_parent = parent_file.read_bytes()
                parent_file.unlink()
                # The configured-PIN query fails before the KeyStore callback,
                # so this still exposes the backend's hardware-failure status.
                expect(0xF3, lambda: authorize(ctap, new_pin, ClientPin.PERMISSION.GET_ASSERTION, "example.test"))
                fd = os.open(parent_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(current_parent)
                sign(ctap, new_pin, first)
                print("PASS: missing shared parent rejected; restoring it recovers signing", flush=True)

                pipe.close(); pipe = None
                handles = subprocess.check_output(["tpm2_getcap","-T",tcti,"handles-transient"],text=True)
                sessions = subprocess.check_output(["tpm2_getcap","-T",tcti,"handles-loaded-session"],text=True)
                assert not handles.strip() and not sessions.strip(), "TPM handles leaked after shutdown"

                # Demonstrate the documented limitation, rather than claim PIN change revokes backups.
                current = (state / "v2/authenticator/tpm-parent.bin").read_bytes()
                (state / "v2/authenticator/tpm-parent.bin").write_bytes(old_parent)
                pipe = Pipe(args.binary,state,tcti)
                sign(Ctap2(pipe),pin,first)
                pipe.close(); pipe = None
                (state / "v2/authenticator/tpm-parent.bin").write_bytes(current)
                print("PASS: old-parent rollback limitation reproduced; handles cleaned up",flush=True)

                pipe = Pipe(args.binary,state,tcti,"deny")
                ctap = Ctap2(pipe)
                expect(CtapError.ERR.OPERATION_DENIED,lambda:register(ctap,new_pin,b"must-not-register"))
                expect(CtapError.ERR.OPERATION_DENIED,lambda:sign(ctap,new_pin,first))
                print("PASS: denied presence prevents registration and signing",flush=True)

                pipe.close(); pipe = None
                remaining = 8
                while remaining:
                    pipe = Pipe(args.binary,state,tcti)
                    ctap = Ctap2(pipe)
                    assert ClientPin(ctap).get_pin_retries()[0] == remaining
                    for attempt in range(min(3,remaining)):
                        remaining -= 1
                        expected = CtapError.ERR.PIN_BLOCKED if not remaining else (
                            CtapError.ERR.PIN_AUTH_BLOCKED if attempt == 2 else CtapError.ERR.PIN_INVALID)
                        expect(expected,lambda:authorize(ctap,"wrongpin",ClientPin.PERMISSION.GET_ASSERTION,"example.test"))
                        assert ClientPin(ctap).get_pin_retries()[0] == remaining
                    pipe.close(); pipe = None
                pipe = Pipe(args.binary,state,tcti)
                ctap = Ctap2(pipe)
                expect(CtapError.ERR.PIN_BLOCKED,lambda:authorize(ctap,new_pin,ClientPin.PERMISSION.GET_ASSERTION,"example.test"))
                print("PASS: eight-attempt PIN limit persists across restarts; correct PIN cannot bypass lockout",flush=True)
            finally:
                if pipe:
                    pipe.close()
                sim.terminate()
                sim.wait(timeout=10)


if __name__ == "__main__":
    main()

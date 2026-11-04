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
    def __init__(self, binary, root, tcti, decision="allow"):
        self.proc = subprocess.Popen([str(binary), str(root), tcti, decision],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)

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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expiry", action="store_true", help="also wait 31s to check real token expiry")
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
                pin, new_pin = "12345678", "87654321"
                ClientPin(ctap).set_pin(pin)
                assert ctap.get_info().options["clientPin"]
                print("PASS: native ClientPIN v2 setup", flush=True)

                expect(CtapError.ERR.PIN_INVALID, lambda: authorize(ctap, "wrongpin", ClientPin.PERMISSION.MAKE_CREDENTIAL, "example.test"))
                variable = subprocess.check_output(["tpm2_getcap", "-T", tcti, "properties-variable"],text=True)
                counter = re.search(r"TPM2_PT_LOCKOUT_COUNTER:\s*(0x[0-9a-fA-F]+|\d+)",variable)
                assert counter and int(counter[1],0) >= 1, "wrong PIN did not reach TPM DA protection"
                print("PASS: incorrect PIN rejected by hardware authorization; DA counter increased", flush=True)

                # The public configured-PIN marker is all zeroes; submitting it
                # must still reach TPM authorization and consume a hardware retry.
                client = ClientPin(ctap)
                agreement, secret = client._get_shared_secret()
                expect(CtapError.ERR.PIN_INVALID,lambda:ctap.client_pin(
                    client.protocol.VERSION,ClientPin.CMD.GET_TOKEN_USING_PIN,
                    key_agreement=agreement,pin_hash_enc=client.protocol.encrypt(secret,bytes(16)),
                    permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,permissions_rpid="example.test"))
                variable = subprocess.check_output(["tpm2_getcap","-T",tcti,"properties-variable"],text=True)
                counter = re.search(r"TPM2_PT_LOCKOUT_COUNTER:\s*(0x[0-9a-fA-F]+|\d+)",variable)
                assert counter and int(counter[1],0) >= 2, "configured-PIN marker bypassed TPM verification"
                print("PASS: configured-PIN marker cannot authorize; zero candidate is rejected by TPM",flush=True)

                first = register(ctap,pin,b"first-account")
                second = register(ctap,pin,b"second-account")
                sign(ctap,pin,first)
                sign(ctap,pin,second)
                assert not (state / "v1" / "02045").exists(), "software PIN verifier was written"
                h = hashlib.sha256(pin.encode()).digest()[:16]
                assert all(h not in f.read_bytes() for f in (state / "v1").iterdir())
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

                old_parent = (state / "v1" / "65536").read_bytes()
                before = {f.name:f.read_bytes() for f in (state / "v1").iterdir() if 1700 <= int(f.name) < 2000}
                # Exercise the existing forced-change comparison through KeyStore:
                # it may compare only the candidate just verified by TPM, not the marker.
                force = state / "v1" / "02040"
                os.close(os.open(force,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600))
                expect(CtapError.ERR.PIN_POLICY_VIOLATION,lambda:ClientPin(ctap).change_pin(pin,pin))
                assert force.exists()
                ClientPin(ctap).change_pin(pin,new_pin)
                assert not force.exists(), "successful PIN change did not clear forced-change state"
                assert before == {f.name:f.read_bytes() for f in (state / "v1").iterdir() if 1700 <= int(f.name) < 2000}
                sign(ctap,new_pin,first)
                pipe.close(); pipe = None
                pipe = Pipe(args.binary,state,tcti)
                ctap = Ctap2(pipe)
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

                # Corrupt only the TPM private blob, preserving its public point/template.
                # Unexpected hardware failure must stop the process before any signature escapes.
                record_file = next(f for f in (state / "v1").iterdir()
                                   if 1700 <= int(f.name) < 2000 and cbor.decode(f.read_bytes())[0] == first.credential_id)
                original = record_file.read_bytes()
                record = cbor.decode(original)
                algorithm, encoded = record[12]
                wrapped = cbor.decode(encoded)
                damaged = bytearray(wrapped[2]); damaged[-1] ^= 1; wrapped[2] = bytes(damaged)
                record[12] = [algorithm,cbor.encode(wrapped)]
                record_file.write_bytes(cbor.encode(record))
                try:
                    sign(ctap,new_pin,first)
                except RuntimeError as error:
                    assert "Rust test bridge exited" in str(error)
                else:
                    raise AssertionError("corrupted hardware key did not stop the service")
                pipe.close(expected=1); pipe = None
                # This disposable TCP simulator has no Linux resource manager to
                # flush the long-lived primary when the daemon's device fd closes.
                subprocess.run(["tpm2_flushcontext","-T",tcti,"-t"],check=True)
                record_file.write_bytes(original)
                pipe = Pipe(args.binary,state,tcti)
                ctap = Ctap2(pipe)
                # A token obtained before the crash must not survive restart.
                digest = os.urandom(32)
                expect(CtapError.ERR.PIN_AUTH_INVALID,lambda:ctap.get_assertion(
                    "example.test",digest,[{"id":first.credential_id,"type":"public-key"}],
                    pin_uv_param=protocol.authenticate(token,digest),pin_uv_protocol=protocol.VERSION))
                sign(ctap,new_pin,first)
                print("PASS: TPM failure exits with status 1; restart rejects old tokens and signs after fresh PIN",flush=True)

                pipe.close(); pipe = None
                handles = subprocess.check_output(["tpm2_getcap","-T",tcti,"handles-transient"],text=True)
                sessions = subprocess.check_output(["tpm2_getcap","-T",tcti,"handles-loaded-session"],text=True)
                assert not handles.strip() and not sessions.strip(), "TPM handles leaked after shutdown"

                # Demonstrate the documented limitation, rather than claim PIN change revokes backups.
                current = (state / "v1" / "65536").read_bytes()
                (state / "v1" / "65536").write_bytes(old_parent)
                pipe = Pipe(args.binary,state,tcti)
                sign(Ctap2(pipe),pin,first)
                pipe.close(); pipe = None
                (state / "v1" / "65536").write_bytes(current)
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

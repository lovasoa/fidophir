#!/usr/bin/python3
"""Exercise the real GIO adapter on a PRIVATE test bus with fake login1/polkit.

No messages reach the desktop's real bus, agent, PAM stack or fingerprint reader.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from interop import Pipe, Ctap2, ClientPin, CtapError, expect, register, sign, free_ports

MANAGER = """<node><interface name='org.freedesktop.login1.Manager'>
<method name='ListSessions'><arg type='a(susso)' direction='out'/></method>
</interface></node>"""
SESSION = """<node><interface name='org.freedesktop.login1.Session'>
<property name='Id' type='s' access='read'/><property name='User' type='(uo)' access='read'/>
<property name='Seat' type='(so)' access='read'/><property name='Active' type='b' access='read'/>
<property name='Remote' type='b' access='read'/><property name='LockedHint' type='b' access='read'/>
<property name='Class' type='s' access='read'/><property name='Type' type='s' access='read'/>
</interface></node>"""
AUTHORITY = """<node><interface name='org.freedesktop.PolicyKit1.Authority'>
<method name='CheckAuthorization'><arg type='(sa{sv})' direction='in'/><arg type='s' direction='in'/>
<arg type='a{ss}' direction='in'/><arg type='u' direction='in'/><arg type='s' direction='in'/>
<arg type='(bba{ss})' direction='out'/></method>
<method name='CancelCheckAuthorization'><arg type='s' direction='in'/></method>
</interface></node>"""


def serve(address, folder):
    import gi
    from gi.repository import Gio, GLib
    connection = Gio.DBusConnection.new_for_address_sync(address,
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,None,None)
    folder = Path(folder)
    state = {"mode":None,"locked":False}

    def mode():
        value = (folder / "mode").read_text().strip()
        if value != state["mode"]:
            state.update(mode=value,locked=False)
        return value

    def event(kind, **values):
        with (folder / "events").open("a") as file:
            file.write(json.dumps({"kind":kind,"time":time.monotonic(),**values})+"\n")

    def method(conn,sender,path,interface,name,params,invocation):
        current = mode()
        if name == "ListSessions":
            owner = os.geteuid() + (1 if current == "other_uid" else 0)
            rows = [("one",owner,"synthetic","seat0","/org/freedesktop/login1/session/one")]
            if current == "ambiguous":
                rows.append(("two",owner,"synthetic","seat0","/org/freedesktop/login1/session/two"))
            invocation.return_value(GLib.Variant("(a(susso))",(rows,)))
        elif name == "CancelCheckAuthorization":
            event("cancel",id=params.unpack()[0]); invocation.return_value(GLib.Variant("()",()))
        elif name == "CheckAuthorization":
            subject,action,details,flags,nonce = params.unpack()
            assert subject == ("unix-session",{"session-id":"one"})
            assert action == "org.local.fidophir.use"
            event("check",mode=current,flags=flags,id=nonce,details=details)
            extra = {}
            if flags == 0:
                authorized,challenge = current == "silent", current not in ("silent","no_agent")
                if current == "retained": extra["polkit.retains_authorization_after_challenge"] = "1"
            else:
                authorized,challenge = current not in ("deny","slow_deny"),False
                if current == "temporary": extra["polkit.temporary_authorization_id"] = "synthetic"
                if current == "locks_after": state["locked"] = True

            def answer():
                event("reply",id=nonce,mode=current,flags=flags)
                invocation.return_value(GLib.Variant("((bba{ss}))",((authorized,challenge,extra),)))
                return False

            if flags and current in ("slow","slow_deny"):
                # Deliberately reply after cancellation to exercise stale-result handling.
                GLib.timeout_add(300 if current == "slow" else 450,answer)
            else:
                answer()

    def prop(conn,sender,path,interface,name):
        current = mode()
        properties = {
            "Id":GLib.Variant("s",path.rsplit("/",1)[-1]),
            "User":GLib.Variant("(uo)",(os.geteuid(),"/org/freedesktop/login1/user/_1000")),
            "Seat":GLib.Variant("(so)",("seat0","/org/freedesktop/login1/seat/seat0")),
            "Active":GLib.Variant("b",current != "inactive"),
            "Remote":GLib.Variant("b",current == "remote"),
            "LockedHint":GLib.Variant("b",current == "locked" or state["locked"]),
            "Class":GLib.Variant("s","user"),"Type":GLib.Variant("s","wayland"),
        }
        return properties[name]

    for name in ("org.freedesktop.login1","org.freedesktop.PolicyKit1"):
        connection.call_sync("org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus",
            "RequestName",GLib.Variant("(su)",(name,0)),None,Gio.DBusCallFlags.NONE,1000,None)
    registrations = []
    for path,xml,callback,getter in [
        ("/org/freedesktop/login1",MANAGER,method,None),
        ("/org/freedesktop/login1/session/one",SESSION,None,prop),
        ("/org/freedesktop/login1/session/two",SESSION,None,prop),
        ("/org/freedesktop/PolicyKit1/Authority",AUTHORITY,method,None)]:
        registrations.append(connection.register_object(path,Gio.DBusNodeInfo.new_for_xml(xml).interfaces[0],callback,getter,None))
    print("READY",flush=True)
    GLib.MainLoop().run()


def main(binary):
    os.environ["TSS2_LOG"] = "all+NONE"
    with tempfile.TemporaryDirectory(prefix="mf-desktop-",dir="/tmp") as directory:
        folder = Path(directory)
        (folder / "mode").write_text("allow")
        (folder / "events").write_text("")
        (folder / "simulator").mkdir(mode=0o700)
        (folder / "records").mkdir(mode=0o700)
        port = free_ports()
        tcti = f"swtpm:host=127.0.0.1,port={port}"
        address = f"unix:path={folder}/bus"
        bus = subprocess.Popen(["dbus-daemon","--session","--nofork","--print-address=1",f"--address={address}"],stdout=subprocess.PIPE,text=True)
        address = bus.stdout.readline().strip()
        server = subprocess.Popen([sys.executable,__file__,"--serve",address,str(folder)],stdout=subprocess.PIPE,text=True)
        sim = subprocess.Popen(["swtpm","socket","--tpm2","--tpmstate",f"dir={folder / 'simulator'}",
            "--server",f"type=tcp,port={port},bindaddr=127.0.0.1",
            "--ctrl",f"type=tcp,port={port+1},bindaddr=127.0.0.1","--flags","not-need-init,startup-clear"],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        pipe = None
        old_address = os.environ.get("DBUS_SYSTEM_BUS_ADDRESS")
        try:
            assert server.stdout.readline().strip() == "READY"
            time.sleep(0.2)
            # Child GIO's SYSTEM connection goes only to this isolated fake bus.
            os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = address
            pipe = Pipe(binary,folder / "records",tcti,"native")
            ctap = Ctap2(pipe)
            ClientPin(ctap).set_pin("12345678")
            key = register(ctap,"12345678",b"native-adapter")
            sign(ctap,"12345678",key)
            print("PASS: real GIO login1/polkit wire flow, RP context and successful approval",flush=True)

            for mode in ("silent","retained","temporary","deny","locked","inactive","remote","other_uid","ambiguous","no_agent","locks_after"):
                (folder / "mode").write_text(mode)
                expect(CtapError.ERR.OPERATION_DENIED,lambda:register(ctap,"12345678",b"must-not-register"))
                print(f"PASS: native adapter rejects {mode}",flush=True)

            pipe.close(); pipe = None
            (folder / "mode").write_text("slow")
            pipe = Pipe(binary,folder / "records",tcti,"native-cancel")
            ctap = Ctap2(pipe)
            expect(CtapError.ERR.KEEPALIVE_CANCEL,lambda:register(ctap,"12345678",b"cancelled"))
            (folder / "mode").write_text("slow_deny")
            expect(CtapError.ERR.OPERATION_DENIED,lambda:sign(ctap,"12345678",key))
            events = [json.loads(line) for line in (folder / "events").read_text().splitlines()]
            assert any(e["kind"] == "cancel" for e in events)
            assert any(e["kind"] == "reply" and e.get("mode") == "slow" and e.get("flags") == 1 for e in events)
            assert any(e["kind"] == "check" and e["details"]["rp"] == " for example.test" for e in events)
            print("PASS: CANCEL reaches polkit; a late success cannot approve the next denied request",flush=True)
        finally:
            if pipe: pipe.close()
            for proc in (server,sim,bus):
                proc.terminate(); proc.wait(timeout=10)
            server.stdout.close(); bus.stdout.close()
            if old_address is None: os.environ.pop("DBUS_SYSTEM_BUS_ADDRESS",None)
            else: os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = old_address


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--serve":
        serve(sys.argv[2],sys.argv[3])
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("--binary",required=True,type=Path)
        main(parser.parse_args().binary)

// SPDX-License-Identifier: Apache-2.0
use fidophir::{
    Error, Result,
    env::LinuxEnv,
    io::{Io, dispatch_desktop},
};
use opensk::ctap::hid::{CtapHidCommand, HidPacketIterator, Message};
use opensk::ctap::{CtapState, main_hid::MainHid};
use std::{path::PathBuf, time::Duration};

fn run() -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        return Err(Error::Invalid(
            "run through the unprivileged fidophir system service",
        ));
    }
    if std::env::args_os().len() != 1 {
        return Err(Error::Invalid("fidophir takes no command-line options"));
    }
    nix::sys::prctl::set_dumpable(false).map_err(std::io::Error::from)?;
    let uid: u32 = std::env::var("FIDOPHIR_OWNER_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|uid| *uid != 0 && *uid != nix::unistd::geteuid().as_raw())
        .ok_or(Error::Invalid(
            "FIDOPHIR_OWNER_UID must name a non-service, non-root owner",
        ))?;
    let seat = std::env::var("FIDOPHIR_OWNER_SEAT")
        .map_err(|_| Error::Invalid("missing FIDOPHIR_OWNER_SEAT"))?;
    if seat.is_empty()
        || seat.len() > 64
        || !seat
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(Error::Invalid("invalid owner seat"));
    }
    let context = glib::MainContext::default();
    let _guard = context
        .acquire()
        .map_err(|_| Error::Invalid("desktop main context unavailable"))?;
    let io = Io::shared();
    let mut env = LinuxEnv::new(PathBuf::from("/var/lib/fidophir"), io.clone(), uid, seat)?;
    let mut state = CtapState::new(&mut env);
    let mut hid = MainHid::default();
    io.borrow_mut().publish()?;
    eprintln!("fidophir: authenticator ready");
    loop {
        dispatch_desktop();
        state.can_sleep(&mut env);
        let packet = io.borrow_mut().receive()?;
        if let Some(packet) = packet {
            let cid = packet[..4].try_into().expect("fixed HID packet");
            io.borrow_mut().enter(cid);
            let frames = hid.process_hid_packet(&mut env, &packet, false, &mut state);
            let frames = if io.borrow().cancelled() {
                HidPacketIterator::new(Message {
                    cid,
                    cmd: CtapHidCommand::Cbor,
                    payload: vec![
                        opensk::ctap::status_code::Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL
                            as u8,
                    ],
                })
                .expect("single-byte response")
            } else {
                frames
            };
            for frame in frames {
                io.borrow_mut().send(&frame)?;
            }
            io.borrow_mut().leave();
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fidophir: {error}");
        std::process::exit(1);
    }
}

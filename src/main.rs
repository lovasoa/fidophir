// SPDX-License-Identifier: Apache-2.0
use fidophir::{
    Error, Result,
    env::LinuxEnv,
    io::{Io, dispatch_desktop},
    opensk_adapter::Authenticator,
};
use std::{path::PathBuf, time::Duration};

fn run() -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        return Err(Error::Invalid(
            "run through the unprivileged fidophir system service",
        ));
    }
    nix::sys::prctl::set_dumpable(false).map_err(std::io::Error::from)?;
    let args: Vec<String> = std::env::args().collect();
    let uid = if args.len() == 3 && args[1] == "--user" {
        args[2]
            .parse::<u32>()
            .ok()
            .filter(|uid| *uid != 0 && *uid != nix::unistd::geteuid().as_raw())
    } else {
        None
    }
    .ok_or(Error::Invalid("invalid user instance"))?;
    let root = std::env::var_os("STATE_DIRECTORY")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && !p.as_os_str().as_encoded_bytes().contains(&b':'))
        .ok_or(Error::Invalid(
            "systemd must supply one absolute STATE_DIRECTORY",
        ))?;
    let context = glib::MainContext::default();
    let _guard = context
        .acquire()
        .map_err(|_| Error::Invalid("desktop main context unavailable"))?;
    let io = Io::shared();
    let mut env = LinuxEnv::new(root, io.clone(), uid)?;
    let mut authenticator = Authenticator::new(&mut env);
    io.borrow_mut().publish(uid)?;
    fidophir::logging::write(
        fidophir::logging::Level::Info,
        format_args!("authenticator ready"),
    );
    loop {
        dispatch_desktop();
        env.backend
            .expire_pin_authorization(fidophir::io::boot_ms());
        let packet = io.borrow_mut().receive()?;
        if let Some(packet) = packet {
            let cid = packet[..4].try_into().expect("fixed HID packet");
            io.borrow_mut().enter(cid);
            let frames = authenticator.process_hid_packet(&mut env, &packet);
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
        fidophir::logging::write(fidophir::logging::Level::Error, format_args!("{error}"));
        std::process::exit(1);
    }
}

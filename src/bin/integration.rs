// SPDX-License-Identifier: Apache-2.0
//! Test-only CBOR pipe transport for independent FIDO clients; never packaged.
use fidophir::{env::LinuxEnv, io::Io};
use opensk::ctap::hid::{CtapHid, CtapHidCommand, HidPacketIterator, Message, MessageAssembler};
use opensk::ctap::{CtapState, main_hid::MainHid};
use std::io::{Read, Write};

fn exchange(
    env: &mut LinuxEnv,
    state: &mut CtapState<LinuxEnv>,
    hid: &mut MainHid<LinuxEnv>,
    io: &fidophir::io::SharedIo,
    message: Message,
) -> Message {
    let mut assembler = MessageAssembler::<LinuxEnv>::default();
    let mut answer = None;
    for frame in HidPacketIterator::new(message).expect("bounded test request") {
        io.borrow_mut().enter(frame[..4].try_into().unwrap());
        for reply in hid.process_hid_packet(env, &frame, false, state) {
            let (cid, packet) = CtapHid::<LinuxEnv>::process_single_packet(&reply);
            if let Some(message) = assembler
                .parse_packet(env, cid, packet)
                .expect("test response framing")
            {
                answer = Some(message);
            }
        }
        io.borrow_mut().leave();
    }
    answer.expect("test command response")
}

fn main() {
    nix::sys::prctl::set_dumpable(false).expect("nondumpable test process");
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "integration runner: STATE_ROOT SWTPM_TCTI allow|deny"
    );
    let context = glib::MainContext::default();
    let _guard = context.acquire().expect("test main context");
    let io = Io::shared();
    let mut env = if args[3].starts_with("native") {
        LinuxEnv::for_test_native(args[1].clone().into(), &args[2], io.clone())
    } else {
        LinuxEnv::for_test(
            args[1].clone().into(),
            &args[2],
            io.clone(),
            args[3] == "allow",
        )
    }
    .expect("test environment");
    let mut state = CtapState::new(&mut env);
    let mut hid = MainHid::default();
    let init = exchange(
        &mut env,
        &mut state,
        &mut hid,
        &io,
        Message {
            cid: [0xff; 4],
            cmd: CtapHidCommand::Init,
            payload: vec![0; 8],
        },
    );
    let cid: [u8; 4] = init.payload[8..12]
        .try_into()
        .expect("allocated test channel");
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut length = [0u8; 4];
        match input.read_exact(&mut length) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("{e}"),
        }
        let length = u32::from_be_bytes(length) as usize;
        assert!((1..=7609).contains(&length));
        let mut bytes = vec![0; length];
        input.read_exact(&mut bytes).expect("test input");
        state.can_sleep(&mut env);
        if args[3] == "native-cancel" && bytes[0] == 1 {
            let io = io.clone();
            glib::timeout_add_local_once(std::time::Duration::from_millis(150), move || {
                let mut cancel = [0u8; 64];
                cancel[..4].copy_from_slice(&cid);
                cancel[4] = 0x91;
                io.borrow_mut().inject(cancel);
            });
        }
        let response = exchange(
            &mut env,
            &mut state,
            &mut hid,
            &io,
            Message {
                cid,
                cmd: CtapHidCommand::Cbor,
                payload: bytes,
            },
        );
        let response = if io.borrow().cancelled() {
            vec![0x2d]
        } else {
            response.payload
        };
        output
            .write_all(&(response.len() as u32).to_be_bytes())
            .expect("test output");
        output.write_all(&response).expect("test output");
        output.flush().expect("test output");
    }
}

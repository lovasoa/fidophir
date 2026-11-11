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


use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
 unsafe fn alloc(&self, l: Layout) -> *mut u8 {
  let p = unsafe { System.alloc(l) };
  if !p.is_null() { let n=LIVE.fetch_add(l.size(),Relaxed)+l.size(); PEAK.fetch_max(n,Relaxed); COUNT.fetch_add(1,Relaxed); } p
 }
 unsafe fn dealloc(&self,p:*mut u8,l:Layout) { LIVE.fetch_sub(l.size(),Relaxed); COUNT.fetch_sub(1,Relaxed); unsafe { System.dealloc(p,l) }; }
 unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8 {
  let q=unsafe {System.realloc(p,l,n)};
  if !q.is_null() { let v=LIVE.fetch_add(n,Relaxed)+n; LIVE.fetch_sub(l.size(),Relaxed); PEAK.fetch_max(v-l.size(),Relaxed); } q
 }
}
#[global_allocator] static ALLOC: Counting=Counting;
#[repr(C)] #[derive(Debug)] struct MallInfo { arena:usize,ordblks:usize,smblks:usize,hblks:usize,hblkhd:usize,usmblks:usize,fsmblks:usize,uordblks:usize,fordblks:usize,keepcost:usize }
unsafe extern "C" { fn mallinfo2()->MallInfo; fn malloc_trim(pad:usize)->i32; }
fn dump_proc(path:&str) {
 let mut f=std::fs::File::open(path).unwrap();
 let mut buf=[0u8;8192]; let mut out=std::io::stderr().lock();
 loop {let n=f.read(&mut buf).unwrap(); if n==0 {break} out.write_all(&buf[..n]).unwrap();}
}
fn snapshot(label:&str) {
 let live=LIVE.load(Relaxed); let peak=PEAK.load(Relaxed); let count=COUNT.load(Relaxed);
 eprintln!("PROFILE {label} rust_live={live} rust_peak={peak} rust_count={count} glibc={:?}",unsafe {mallinfo2()});
 eprintln!("ROLLUP {label}"); dump_proc("/proc/self/smaps_rollup");
 if label=="startup" || label=="trimmed" {eprintln!("SMAPS {label}"); dump_proc("/proc/self/smaps"); eprintln!("END_SMAPS");}
}

fn main() {
 snapshot("before_init");
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
    snapshot("environment");
    let mut state = CtapState::new(&mut env);
    snapshot("ctap_state");
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
    snapshot("startup");
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
        if bytes[0] == 0xfe || bytes[0] == 0xfd {
            if bytes[0] == 0xfe { for _ in 0..350 { fidophir::io::dispatch_desktop(); state.can_sleep(&mut env); std::thread::sleep(std::time::Duration::from_millis(100)); } snapshot("idle35s"); }
            else { unsafe { malloc_trim(0); } snapshot("trimmed"); }
            output.write_all(&1u32.to_be_bytes()).unwrap(); output.write_all(&[0]).unwrap(); output.flush().unwrap(); continue;
        }
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
        let profile_command = bytes[0];
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
        snapshot(&format!("command_{:02x}",profile_command));
    }
}

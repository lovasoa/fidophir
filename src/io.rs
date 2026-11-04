// SPDX-License-Identifier: Apache-2.0
//! UHID event mapping. CTAPHID parsing, errors and keepalives come from OpenSK.
use crate::{Error, Result};
use opensk::ctap::hid::{CtapHid, CtapHidCommand, KeepaliveStatus, ProcessedPacket};
use std::{cell::RefCell, fs::File, rc::Rc};
use uhid_virt::{
    Bus, CreateParams, DevFlags, OutputEvent, StreamError, UHID_EVENT_SIZE, UHIDDevice,
};

pub type SharedIo = Rc<RefCell<Io>>;

const DESCRIPTOR: &[u8] = &[
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xc0,
];

#[derive(Default)]
pub struct Io {
    device: Option<UHIDDevice<File>>,
    current: Option<[u8; 4]>,
    cancelled: bool,
    next_keepalive: u64,
    #[cfg(any(test, feature = "integration-tests"))]
    input: std::collections::VecDeque<[u8; 64]>,
    #[cfg(test)]
    output: Vec<[u8; 64]>,
}

pub fn boot_ms() -> u64 {
    let t = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
        .expect("CLOCK_BOOTTIME unavailable");
    (t.tv_sec() as u64).saturating_mul(1000) + t.tv_nsec() as u64 / 1_000_000
}

pub fn dispatch_desktop() {
    let context = glib::MainContext::default();
    for _ in 0..16 {
        if !context.pending() {
            break;
        }
        context.iteration(false);
    }
}

// hidraw output includes report ID zero for this unnumbered descriptor.
// Accept a bare report too; never strip a nonzero ID or truncate a report.
fn output_packet(data: &[u8]) -> Option<[u8; 64]> {
    match data {
        [0, report @ ..] if report.len() == 64 => report.try_into().ok(),
        report => report.try_into().ok(),
    }
}

impl Io {
    pub fn shared() -> SharedIo {
        Rc::new(RefCell::new(Self::default()))
    }

    pub fn publish(&mut self, uid: u32) -> Result<()> {
        self.device = Some(UHIDDevice::create(CreateParams {
            name: "Fidophir TPM".into(),
            phys: "fidophir-v2".into(),
            uniq: uid.to_string(),
            bus: Bus::VIRTUAL,
            vendor: 0,
            product: 1,
            version: 1,
            country: 0,
            rd_data: DESCRIPTOR.to_vec(),
        })?);
        Ok(())
    }

    pub fn enter(&mut self, cid: [u8; 4]) {
        self.current = Some(cid);
        self.cancelled = false;
        self.next_keepalive = boot_ms();
    }
    pub fn leave(&mut self) {
        self.current = None;
    }
    pub fn cancelled(&self) -> bool {
        self.cancelled
    }

    pub fn send(&mut self, frame: &[u8; 64]) -> Result<()> {
        #[cfg(test)]
        {
            self.output.push(*frame);
        }
        if let Some(device) = self.device.as_mut()
            && device.write(frame)? != UHID_EVENT_SIZE
        {
            return Err(Error::Invalid("short UHID event write"));
        }
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Option<[u8; 64]>> {
        #[cfg(any(test, feature = "integration-tests"))]
        if let Some(packet) = self.input.pop_front() {
            return Ok(Some(packet));
        }
        let Some(device) = self.device.as_mut() else {
            return Ok(None);
        };
        for _ in 0..16 {
            match device.read() {
                Ok(OutputEvent::Output { data }) => {
                    if let Some(packet) = output_packet(&data) {
                        return Ok(Some(packet));
                    }
                }
                Ok(OutputEvent::GetReport { id, .. }) => {
                    if device.write_get_report_reply(id, nix::libc::EIO as u16, Vec::new())?
                        != UHID_EVENT_SIZE
                    {
                        return Err(Error::Invalid("short UHID control reply"));
                    }
                }
                Ok(OutputEvent::SetReport { id, .. }) => {
                    if device.write_set_report_reply(id, nix::libc::EIO as u16)? != UHID_EVENT_SIZE
                    {
                        return Err(Error::Invalid("short UHID control reply"));
                    }
                }
                Ok(OutputEvent::Start { dev_flags }) => {
                    if dev_flags.iter().any(|f| {
                        matches!(
                            f,
                            DevFlags::InputReportsNumbered | DevFlags::OutputReportsNumbered
                        )
                    }) {
                        return Err(Error::Invalid("unexpected numbered UHID reports"));
                    }
                }
                Ok(OutputEvent::Stop) => return Err(Error::Invalid("UHID stopped")),
                Ok(_) => (),
                Err(StreamError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(StreamError::Io(e)) => return Err(e.into()),
                Err(StreamError::UnknownEventType(_)) => {
                    return Err(Error::Invalid("unknown UHID event"));
                }
            }
        }
        Ok(None)
    }

    /// Called only while the core is inside a blocking backend callback.
    pub fn busy(&mut self) -> Result<()> {
        let Some(cid) = self.current else {
            return Ok(());
        };
        if let Some(packet) = self.receive()? {
            let (received, event) = CtapHid::<crate::env::LinuxEnv>::process_single_packet(&packet);
            if received != cid {
                for packet in CtapHid::<crate::env::LinuxEnv>::busy_error(received) {
                    self.send(&packet)?;
                }
            } else if matches!(event, ProcessedPacket::InitPacket {cmd, ..} if cmd == CtapHidCommand::Cancel as u8)
            {
                self.cancelled = true;
            }
        }
        let now = boot_ms();
        if now >= self.next_keepalive {
            for packet in
                CtapHid::<crate::env::LinuxEnv>::keepalive(cid, KeepaliveStatus::Processing)
            {
                self.send(&packet)?;
            }
            self.next_keepalive = now.saturating_add(100);
        }
        Ok(())
    }

    #[cfg(any(test, feature = "integration-tests"))]
    pub fn inject(&mut self, packet: [u8; 64]) {
        self.input.push_back(packet);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalize_only_exact_unnumbered_output_reports() {
        let report = [0xa5; 64];
        assert_eq!(output_packet(&report), Some(report));
        let mut numbered = vec![0];
        numbered.extend(report);
        assert_eq!(output_packet(&numbered), Some(report));
        numbered[0] = 1;
        assert!(output_packet(&numbered).is_none());
        assert!(output_packet(&[0; 63]).is_none());
        assert!(output_packet(&[0; 66]).is_none());
    }
    fn cancel(cid: [u8; 4]) -> [u8; 64] {
        let mut frame = [0; 64];
        frame[..4].copy_from_slice(&cid);
        frame[4] = 0x91;
        frame
    }

    #[test]
    fn busy_channels_and_keepalive_do_not_cross_cancel() {
        let mut io = Io::default();
        let active = [1, 2, 3, 4];
        let other = [5, 6, 7, 8];
        io.enter(active);
        io.inject(cancel(other));
        io.busy().unwrap();
        assert!(!io.cancelled());
        assert!(
            io.output
                .iter()
                .any(|f| f[..4] == other && f[4] == 0xbf && f[7] == 0x06)
        );
        assert!(
            io.output
                .iter()
                .any(|f| f[..4] == active && f[4] == 0xbb && f[7] == 0x01)
        );
        let mut continuation = cancel(active);
        continuation[4] = 0x11;
        io.inject(continuation);
        io.busy().unwrap();
        assert!(!io.cancelled());
        io.inject(cancel(active));
        io.busy().unwrap();
        assert!(io.cancelled());
        io.leave();
        io.enter(other);
        assert!(!io.cancelled());
    }
}

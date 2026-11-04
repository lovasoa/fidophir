// SPDX-License-Identifier: Apache-2.0
//! Native GNOME approval through the system polkit agent. No UI or PAM code here.
use crate::{
    Error, Result,
    io::{SharedIo, boot_ms, dispatch_desktop},
};
use gio::{DBusCallFlags, DBusConnection};
use glib::{
    Variant,
    variant::{ObjectPath, ToVariant},
};
use opensk::{
    api::{
        connection::{RecvStatus, UsbEndpoint},
        user_presence::*,
    },
    ctap::status_code::Ctap2StatusCode,
};
use rand::{TryRng, rngs::SysRng};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
    time::Duration,
};

const ACTION: &str = "org.local.fidophir.use";
const AUTHORITY: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT: &str = "org.freedesktop.PolicyKit1";

async fn call(
    connection: &DBusConnection,
    destination: &str,
    path: &str,
    interface: &str,
    method: &str,
    args: Variant,
    timeout: i32,
) -> Result<Variant> {
    Ok(connection
        .call_future(
            Some(destination),
            path,
            interface,
            method,
            Some(&args),
            None,
            DBusCallFlags::NONE,
            timeout,
        )
        .await?)
}

#[derive(Clone)]
struct Session {
    id: String,
    path: ObjectPath,
}

async fn eligible(connection: &DBusConnection, session: &Session, uid: u32) -> Result<bool> {
    let reply = call(
        connection,
        "org.freedesktop.login1",
        &session.path,
        "org.freedesktop.DBus.Properties",
        "GetAll",
        ("org.freedesktop.login1.Session",).to_variant(),
        1000,
    )
    .await?;
    let (p,) = reply
        .get::<(HashMap<String, Variant>,)>()
        .ok_or(Error::Invalid("invalid login1 properties"))?;
    let user = p
        .get("User")
        .and_then(|v| v.get::<(u32, ObjectPath)>())
        .map(|v| v.0);
    let session_seat = p
        .get("Seat")
        .and_then(|v| v.get::<(String, ObjectPath)>())
        .map(|v| v.0);
    let text = |key| p.get(key).and_then(|v| v.get::<String>());
    let flag = |key| p.get(key).and_then(|v| v.get::<bool>());
    Ok(user == Some(uid)
        && session_seat.as_ref().is_some_and(|s| !s.is_empty())
        && text("Id").as_deref() == Some(&session.id)
        && flag("Active") == Some(true)
        && flag("Remote") == Some(false)
        && flag("LockedHint") == Some(false)
        && text("Class").as_deref() == Some("user")
        && matches!(text("Type").as_deref(), Some("wayland" | "x11")))
}

// Bind polkit to a live, unprivileged process in the selected login1 session.
// Session subjects crash polkit 127; the session leader can be a root GDM worker.
fn process_start(pid: u32, uid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let ids = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    if !ids
        .split_whitespace()
        .all(|id| id.parse::<u32>() == Ok(uid))
    {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

async fn process_in_session(connection: &DBusConnection, pid: u32, session: &Session) -> bool {
    call(
        connection,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
        "GetSessionByPID",
        (pid,).to_variant(),
        1000,
    )
    .await
    .ok()
    .and_then(|reply| reply.get::<(ObjectPath,)>())
    .is_some_and(|(path,)| path == session.path)
}

async fn session_process(
    connection: &DBusConnection,
    uid: u32,
    session: &Session,
) -> Result<(u32, u64)> {
    for entry in std::fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(start) = process_start(pid, uid) else {
            continue;
        };
        if process_in_session(connection, pid, session).await
            && process_start(pid, uid) == Some(start)
        {
            return Ok((pid, start));
        }
    }
    Err(Error::Invalid("no user process in desktop session"))
}

async fn authorize(
    connection: DBusConnection,
    uid: u32,
    cancellation: String,
    operation: String,
    rp: String,
) -> Result<()> {
    let response = call(
        &connection,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
        "ListSessions",
        ().to_variant(),
        1000,
    )
    .await?;
    let (sessions,) = response
        .get::<(Vec<(String, u32, String, String, ObjectPath)>,)>()
        .ok_or(Error::Invalid("invalid login1 session list"))?;
    let mut selected = None;
    for (id, owner, _, _, path) in sessions {
        if owner != uid {
            continue;
        }
        let session = Session { id, path };
        if eligible(&connection, &session, uid).await? {
            if selected.is_some() {
                return Err(Error::Invalid("ambiguous desktop session"));
            }
            selected = Some(session);
        }
    }
    let session = selected.ok_or(Error::Invalid("no eligible desktop session"))?;
    let (pid, start) = session_process(&connection, uid, &session).await?;
    let subject = (
        "unix-process",
        HashMap::from([
            ("pid", pid.to_variant()),
            (
                "uid",
                i32::try_from(uid)
                    .map_err(|_| Error::Invalid("invalid desktop UID"))?
                    .to_variant(),
            ),
            ("start-time", start.to_variant()),
        ]),
    );
    let details = HashMap::from([("operation", operation), ("rp", rp)]);
    for flags in [0u32, 1u32] {
        if process_start(pid, uid) != Some(start)
            || !process_in_session(&connection, pid, &session).await
            || !eligible(&connection, &session, uid).await?
        {
            return Err(Error::Invalid("desktop process changed"));
        }
        let reply = call(
            &connection,
            POLKIT,
            AUTHORITY,
            "org.freedesktop.PolicyKit1.Authority",
            "CheckAuthorization",
            (
                subject.clone(),
                ACTION,
                details.clone(),
                flags,
                &cancellation,
            )
                .to_variant(),
            if flags == 0 { 1000 } else { 30000 },
        )
        .await?;
        let ((authorized, challenge, result),) = reply
            .get::<((bool, bool, HashMap<String, String>),)>()
            .ok_or(Error::Invalid("invalid polkit result"))?;
        let nonempty = |name| result.get(name).is_some_and(|value| !value.is_empty());
        if nonempty("polkit.dismissed")
            || nonempty("polkit.temporary_authorization_id")
            || nonempty("polkit.retains_authorization_after_challenge")
            || (flags == 0 && (authorized || !challenge))
            || (flags == 1 && !authorized)
        {
            return Err(Error::Invalid("fresh desktop authorization refused"));
        }
    }
    if process_start(pid, uid) != Some(start)
        || !process_in_session(&connection, pid, &session).await
        || !eligible(&connection, &session, uid).await?
    {
        return Err(Error::Invalid("desktop session changed"));
    }
    Ok(())
}

struct Pending {
    id: String,
    alive: Rc<Cell<bool>>,
    result: Rc<RefCell<Option<Result<()>>>>,
    task: glib::JoinHandle<()>,
}

pub struct Approval {
    io: SharedIo,
    connection: Option<DBusConnection>,
    uid: u32,
    pending: Option<Pending>,
    start_error: bool,
    operation: Option<&'static str>,
    rp_id: Option<String>,
    #[cfg(any(test, feature = "integration-tests"))]
    test_decision: Option<bool>,
}

impl Approval {
    pub fn new(io: SharedIo, uid: u32) -> Result<Self> {
        let connection = gio::bus_get_sync(gio::BusType::System, gio::Cancellable::NONE)?;
        Ok(Self {
            io,
            connection: Some(connection),
            uid,
            pending: None,
            start_error: false,
            operation: None,
            rp_id: None,
            #[cfg(any(test, feature = "integration-tests"))]
            test_decision: None,
        })
    }
    #[cfg(any(test, feature = "integration-tests"))]
    pub fn for_test(io: SharedIo, allow: bool) -> Self {
        Self {
            io,
            connection: None,
            uid: 0,
            pending: None,
            start_error: false,
            operation: None,
            rp_id: None,
            test_decision: Some(allow),
        }
    }
    pub fn set_context(&mut self, operation: Option<&'static str>, rp: Option<&str>) {
        self.operation = operation;
        self.rp_id = rp.map(str::to_owned);
    }
    fn cancel(&mut self) {
        if let Some(pending) = self.pending.take() {
            pending.alive.set(false);
            pending.task.abort();
            if let Some(connection) = &self.connection {
                connection.call(
                    Some(POLKIT),
                    AUTHORITY,
                    "org.freedesktop.PolicyKit1.Authority",
                    "CancelCheckAuthorization",
                    Some(&(pending.id,).to_variant()),
                    None,
                    DBusCallFlags::NONE,
                    1000,
                    gio::Cancellable::NONE,
                    |_| {},
                );
            }
        }
    }
}

impl UserPresence for Approval {
    fn check_init(&mut self) {
        self.cancel();
        self.start_error = false;
        #[cfg(any(test, feature = "integration-tests"))]
        if self.test_decision.is_some() {
            return;
        }
        let mut nonce = [0u8; 16];
        let rp = match self.rp_id.as_deref() {
            Some(id)
                if id.len() <= 253
                    && !id.is_empty()
                    && id.bytes().all(|b| b.is_ascii_graphic()) =>
            {
                format!(" for {}", glib::markup_escape_text(id))
            }
            Some(_) => {
                self.start_error = true;
                return;
            }
            None => String::new(),
        };
        let Some(operation) = self.operation else {
            self.start_error = true;
            return;
        };
        let operation = operation.to_owned();
        if SysRng.try_fill_bytes(&mut nonce).is_err() {
            self.start_error = true;
            return;
        }
        let id: String = nonce.iter().map(|n| format!("{n:02x}")).collect();
        let alive = Rc::new(Cell::new(true));
        let result = Rc::new(RefCell::new(None));
        let output = result.clone();
        let live = alive.clone();
        let connection = self
            .connection
            .as_ref()
            .expect("native approval connection")
            .clone();
        let uid = self.uid;
        let cancellation = id.clone();
        let task = glib::MainContext::default().spawn_local(async move {
            let answer = authorize(connection, uid, cancellation, operation, rp).await;
            if live.get() {
                if let Err(error) = &answer {
                    eprintln!("fidophir: desktop approval failed: {error}");
                }
                *output.borrow_mut() = Some(answer);
            }
        });
        self.pending = Some(Pending {
            id,
            alive,
            result,
            task,
        });
    }

    fn wait_with_timeout(
        &mut self,
        packet: &mut [u8; 64],
        timeout_ms: usize,
    ) -> UserPresenceWaitResult {
        let deadline = boot_ms().saturating_add(timeout_ms as u64);
        loop {
            // Let the core observe CANCEL before an approval result ready in the same iteration.
            let received = self
                .io
                .borrow_mut()
                .receive()
                .map_err(|_| Ctap2StatusCode::CTAP2_ERR_VENDOR_HARDWARE_FAILURE)?;
            dispatch_desktop();
            let mut outcome = if self.start_error {
                Some(Err(UserPresenceError::Declined))
            } else {
                None
            };
            #[cfg(any(test, feature = "integration-tests"))]
            if let Some(allow) = self.test_decision {
                outcome = Some(if allow {
                    Ok(())
                } else {
                    Err(UserPresenceError::Declined)
                });
            }
            if let Some(pending) = &self.pending
                && let Some(result) = pending.result.borrow_mut().take()
            {
                outcome = Some(result.map_err(|_| UserPresenceError::Declined));
            }
            if let Some(input) = received {
                *packet = input;
                return Ok((
                    outcome.unwrap_or(Err(UserPresenceError::Timeout)),
                    RecvStatus::Received(UsbEndpoint::MainHid),
                ));
            }
            if let Some(result) = outcome {
                return Ok((result, RecvStatus::Timeout));
            }
            if boot_ms() >= deadline {
                return Ok((Err(UserPresenceError::Timeout), RecvStatus::Timeout));
            }
            std::thread::sleep(Duration::from_millis(
                5.min(deadline.saturating_sub(boot_ms())),
            ));
        }
    }
    fn check_complete(&mut self) {
        self.cancel();
    }
}

impl Drop for Approval {
    fn drop(&mut self) {
        self.cancel();
    }
}

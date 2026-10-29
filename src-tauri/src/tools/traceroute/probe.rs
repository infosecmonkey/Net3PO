//! Unprivileged TTL-limited probes, one backend per OS. Each probe uses its
//! own socket (or ICMP handle) and blocks for at most its timeout, so callers
//! run probes on blocking threads.
//!
//! - macOS: ICMP datagram socket. Replies include the IP header; errors quote
//!   our echo, which is matched by ident and sequence.
//! - Linux: ICMP datagram socket when `net.ipv4.ping_group_range` allows it,
//!   otherwise UDP. Router errors arrive on the socket error queue
//!   (`IP_RECVERR`), as in `tracepath`.
//! - Windows: `IcmpSendEcho2` from iphlpapi, which needs no admin rights.

use std::net::Ipv4Addr;
use std::time::Duration;

use thiserror::Error;

use super::core::{IP_ICMP_OVERHEAD, Outcome, ProbeResult};

/// One probe to send.
#[derive(Debug, Clone, Copy)]
pub struct ProbeSpec {
    pub dst: Ipv4Addr,
    pub ttl: u8,
    pub ident: u16,
    pub seq: u16,
    /// Total IP packet size in bytes.
    pub size: u16,
    /// Set the don't-fragment bit (Path MTU probing).
    pub df: bool,
    pub timeout: Duration,
}

impl ProbeSpec {
    fn payload_len(&self) -> usize {
        usize::from(self.size.saturating_sub(IP_ICMP_OVERHEAD))
    }

    fn result(
        &self,
        responder: Option<Ipv4Addr>,
        outcome: Outcome,
        rtt: Option<Duration>,
    ) -> ProbeResult {
        ProbeResult {
            ttl: self.ttl,
            responder,
            outcome,
            rtt_ms: rtt.map(|d| d.as_secs_f64() * 1000.0),
        }
    }

    fn timed_out(&self) -> ProbeResult {
        self.result(None, Outcome::Timeout, None)
    }
}

/// A failure that makes probing impossible (not a lost probe).
#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("{0}")]
    Setup(String),
}

/// Probe method in use on this OS, for display.
pub fn method() -> String {
    imp::method()
}

/// Send one probe and wait for its answer or the timeout.
pub fn probe(spec: &ProbeSpec) -> Result<ProbeResult, ProbeError> {
    imp::probe(spec)
}

#[cfg(unix)]
fn setsockopt_int(
    sock: &socket2::Socket,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: valid fd, pointer and length describe a live c_int.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::io::ErrorKind;
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    use super::super::core::{Outcome, ReplyKind, build_echo, parse_icmp, strip_ipv4_header};
    use super::{ProbeError, ProbeResult, ProbeSpec, setsockopt_int};

    pub fn method() -> String {
        "ICMP echo (unprivileged datagram socket)".to_string()
    }

    pub fn probe(spec: &ProbeSpec) -> Result<ProbeResult, ProbeError> {
        let setup = |what: &str, e: std::io::Error| ProbeError::Setup(format!("{what}: {e}"));
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
            .map_err(|e| setup("could not open an ICMP socket", e))?;
        sock.set_ttl_v4(u32::from(spec.ttl))
            .map_err(|e| setup("could not set TTL", e))?;
        if spec.df {
            setsockopt_int(&sock, libc::IPPROTO_IP, libc::IP_DONTFRAG, 1)
                .map_err(|e| setup("could not set don't-fragment", e))?;
        }

        let pkt = build_echo(spec.ident, spec.seq, spec.payload_len());
        let dst = SockAddr::from(SocketAddrV4::new(spec.dst, 0));
        let start = Instant::now();
        if let Err(e) = sock.send_to(&pkt, &dst) {
            if e.raw_os_error() == Some(libc::EMSGSIZE) {
                return Ok(spec.result(None, Outcome::TooBig(None), None));
            }
            return Err(setup("could not send probe", e));
        }

        let deadline = start + spec.timeout;
        let mut buf = [MaybeUninit::<u8>::uninit(); 4096];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(spec.timed_out());
            }
            sock.set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
                .map_err(|e| setup("could not set timeout", e))?;
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(r) => r,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Ok(spec.timed_out()),
            };
            // SAFETY: recv_from initialized the first n bytes.
            let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
            // macOS ICMP sockets see every ICMP message for this host, so
            // keep only replies that quote our ident and sequence.
            let Some(reply) = strip_ipv4_header(bytes).and_then(parse_icmp) else {
                continue;
            };
            if reply.ident != spec.ident || reply.seq != spec.seq {
                continue;
            }
            let responder: Option<Ipv4Addr> = from.as_socket_ipv4().map(|a| *a.ip());
            let outcome = match reply.kind {
                ReplyKind::EchoReply => Outcome::Reached,
                ReplyKind::TimeExceeded => Outcome::Hop,
                ReplyKind::Unreachable(c) => Outcome::Unreachable(c),
                ReplyKind::FragNeeded(m) => Outcome::TooBig(m),
            };
            return Ok(spec.result(responder, outcome, Some(start.elapsed())));
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::mem::{MaybeUninit, size_of};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::fd::AsRawFd;
    use std::sync::OnceLock;
    use std::time::Instant;

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    use super::super::core::{
        CODE_FRAG_NEEDED, DEST_UNREACHABLE, Outcome, ReplyKind, TIME_EXCEEDED, build_echo,
        parse_icmp,
    };
    use super::{ProbeError, ProbeResult, ProbeSpec, setsockopt_int};

    /// First UDP destination port, as in classic traceroute.
    const UDP_BASE_PORT: u16 = 33434;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Icmp,
        Udp,
    }

    /// ICMP datagram sockets need the user's group in ping_group_range;
    /// detect once and fall back to UDP, which is always unprivileged.
    fn mode() -> Mode {
        static MODE: OnceLock<Mode> = OnceLock::new();
        *MODE.get_or_init(
            || match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
                Ok(_) => Mode::Icmp,
                Err(_) => Mode::Udp,
            },
        )
    }

    pub fn method() -> String {
        match mode() {
            Mode::Icmp => "ICMP echo (unprivileged datagram socket)".to_string(),
            Mode::Udp => "UDP probes (ICMP datagram sockets are not allowed by \
                          net.ipv4.ping_group_range for this user)"
                .to_string(),
        }
    }

    pub fn probe(spec: &ProbeSpec) -> Result<ProbeResult, ProbeError> {
        let setup = |what: &str, e: std::io::Error| ProbeError::Setup(format!("{what}: {e}"));
        let mode = mode();
        let (sock, payload, port) = match mode {
            Mode::Icmp => (
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)),
                // The kernel replaces the ident with the socket's own id.
                build_echo(0, spec.seq, spec.payload_len()),
                0,
            ),
            Mode::Udp => (
                Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)),
                vec![0x4f; spec.payload_len()],
                UDP_BASE_PORT.wrapping_add(u16::from(spec.ttl)),
            ),
        };
        let sock = sock.map_err(|e| setup("could not open a probe socket", e))?;
        sock.set_ttl_v4(u32::from(spec.ttl))
            .map_err(|e| setup("could not set TTL", e))?;
        setsockopt_int(&sock, libc::IPPROTO_IP, libc::IP_RECVERR, 1)
            .map_err(|e| setup("could not enable IP_RECVERR", e))?;
        let pmtu = if spec.df {
            libc::IP_PMTUDISC_PROBE
        } else {
            libc::IP_PMTUDISC_DONT
        };
        setsockopt_int(&sock, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, pmtu)
            .map_err(|e| setup("could not set IP_MTU_DISCOVER", e))?;

        let dst = SockAddr::from(SocketAddrV4::new(spec.dst, port));
        let start = Instant::now();
        if let Err(e) = sock.send_to(&payload, &dst) {
            if e.raw_os_error() == Some(libc::EMSGSIZE) {
                return Ok(spec.result(None, Outcome::TooBig(None), None));
            }
            return Err(setup("could not send probe", e));
        }

        let deadline = start + spec.timeout;
        let fd = sock.as_raw_fd();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(spec.timed_out());
            }
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLERR,
                revents: 0,
            };
            let ms = remaining.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
            // SAFETY: one valid pollfd.
            let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
            if rc < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Ok(spec.timed_out());
            }
            if rc == 0 {
                return Ok(spec.timed_out());
            }
            if pfd.revents & libc::POLLERR != 0
                && let Some(r) = read_error_queue(fd, spec, mode)
            {
                let rtt = start.elapsed();
                return Ok(match r {
                    (ip, Outcome::TooBig(m)) => spec.result(ip, Outcome::TooBig(m), Some(rtt)),
                    (ip, o) => spec.result(ip, o, Some(rtt)),
                });
            }
            if pfd.revents & libc::POLLIN != 0 {
                let mut buf = [MaybeUninit::<u8>::uninit(); 4096];
                let Ok((n, from)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                // SAFETY: recv_from initialized the first n bytes.
                let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                let responder = from.as_socket_ipv4().map(|a| *a.ip());
                let reached = match mode {
                    // Datagram ICMP sockets deliver the reply without an IP
                    // header, already filtered to this socket's id.
                    Mode::Icmp => parse_icmp(bytes)
                        .is_some_and(|r| r.kind == ReplyKind::EchoReply && r.seq == spec.seq),
                    Mode::Udp => responder == Some(spec.dst),
                };
                if reached {
                    return Ok(spec.result(responder, Outcome::Reached, Some(start.elapsed())));
                }
            }
        }
    }

    /// Read one entry from the socket error queue: the ICMP error a router
    /// sent about our probe, with the router's address.
    fn read_error_queue(
        fd: libc::c_int,
        spec: &ProbeSpec,
        mode: Mode,
    ) -> Option<(Option<Ipv4Addr>, Outcome)> {
        let mut data = [0u8; 2048];
        let mut control = [0u64; 64];
        let mut name: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        // SAFETY: zeroed msghdr is valid; every pointer below outlives the call.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&mut name as *mut libc::sockaddr_in).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control) as _;

        // SAFETY: msg points at live buffers sized above.
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
        if n < 0 {
            return None;
        }
        // For ICMP mode the queued data is our own echo; check the sequence.
        if mode == Mode::Icmp {
            let sent = &data[..(n as usize).min(data.len())];
            if sent.len() >= 8 && u16::from_be_bytes([sent[6], sent[7]]) != spec.seq {
                return None;
            }
        }

        // SAFETY: walking the control buffer the kernel filled, with libc's
        // CMSG helpers; reads are unaligned-safe.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let hdr = &*cmsg;
                if hdr.cmsg_level == libc::IPPROTO_IP && hdr.cmsg_type == libc::IP_RECVERR {
                    let ee_ptr = libc::CMSG_DATA(cmsg).cast::<libc::sock_extended_err>();
                    let ee = std::ptr::read_unaligned(ee_ptr);
                    let off_ptr = ee_ptr.add(1).cast::<libc::sockaddr_in>();
                    let off = std::ptr::read_unaligned(off_ptr);
                    let offender = (off.sin_family == libc::AF_INET as libc::sa_family_t)
                        .then(|| Ipv4Addr::from(u32::from_be(off.sin_addr.s_addr)))
                        .filter(|ip| !ip.is_unspecified());
                    return classify(&ee, offender, spec, mode);
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        None
    }

    fn classify(
        ee: &libc::sock_extended_err,
        offender: Option<Ipv4Addr>,
        spec: &ProbeSpec,
        mode: Mode,
    ) -> Option<(Option<Ipv4Addr>, Outcome)> {
        match ee.ee_origin {
            libc::SO_EE_ORIGIN_ICMP => {
                let outcome = match (ee.ee_type, ee.ee_code) {
                    (TIME_EXCEEDED, _) => Outcome::Hop,
                    (DEST_UNREACHABLE, CODE_FRAG_NEEDED) => {
                        Outcome::TooBig(u16::try_from(ee.ee_info).ok().filter(|m| *m >= 68))
                    }
                    // Port unreachable from the target ends a UDP trace.
                    (DEST_UNREACHABLE, 3) if mode == Mode::Udp && offender == Some(spec.dst) => {
                        Outcome::Reached
                    }
                    (DEST_UNREACHABLE, code) => Outcome::Unreachable(code),
                    _ => return None,
                };
                Some((offender, outcome))
            }
            libc::SO_EE_ORIGIN_LOCAL if ee.ee_errno == libc::EMSGSIZE as u32 => Some((
                None,
                Outcome::TooBig(u16::try_from(ee.ee_info).ok().filter(|m| *m >= 68)),
            )),
            _ => None,
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IP_DEST_PORT_UNREACHABLE, IP_FLAG_DF, IP_OPTION_INFORMATION,
        IP_PACKET_TOO_BIG, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT, IcmpCloseHandle, IcmpCreateFile,
        IcmpSendEcho2,
    };

    use super::super::core::Outcome;
    use super::{ProbeError, ProbeResult, ProbeSpec};

    // IP_STATUS codes not worth importing individually.
    const IP_DEST_NET_UNREACHABLE: u32 = 11002;
    const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
    const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
    const IP_DEST_PROHIBITED: u32 = 11019;

    pub fn method() -> String {
        "ICMP echo (IcmpSendEcho2)".to_string()
    }

    /// Closes the ICMP handle on drop.
    struct IcmpHandle(HANDLE);

    impl Drop for IcmpHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from IcmpCreateFile and is closed once.
            unsafe {
                IcmpCloseHandle(self.0);
            }
        }
    }

    pub fn probe(spec: &ProbeSpec) -> Result<ProbeResult, ProbeError> {
        // SAFETY: plain FFI call with no arguments.
        let raw = unsafe { IcmpCreateFile() };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(ProbeError::Setup(format!(
                "IcmpCreateFile failed (error {})",
                // SAFETY: reads the thread's last error.
                unsafe { GetLastError() }
            )));
        }
        let handle = IcmpHandle(raw);

        let payload = vec![b'O'; spec.payload_len()];
        let options = IP_OPTION_INFORMATION {
            Ttl: spec.ttl,
            Tos: 0,
            Flags: if spec.df { IP_FLAG_DF as u8 } else { 0 },
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        };
        // Room for the reply struct, the echoed data, an ICMP error, and the
        // IO_STATUS_BLOCK the API may append. u64 keeps it 8-byte aligned.
        let reply_bytes = std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8 + 64;
        let mut reply_buf = vec![0u64; reply_bytes.div_ceil(8)];
        let timeout_ms = spec.timeout.as_millis().clamp(1, u128::from(u32::MAX)) as u32;

        let start = Instant::now();
        // SAFETY: all pointers reference live buffers of the stated sizes;
        // no event or APC routine, so the call is synchronous.
        let count = unsafe {
            IcmpSendEcho2(
                handle.0,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                u32::from_ne_bytes(spec.dst.octets()),
                payload.as_ptr().cast(),
                payload.len() as u16,
                &options,
                reply_buf.as_mut_ptr().cast(),
                (reply_buf.len() * 8) as u32,
                timeout_ms,
            )
        };
        let rtt = start.elapsed();
        // SAFETY: the buffer is at least one ICMP_ECHO_REPLY and aligned; the
        // API fills it even when it reports an ICMP error status.
        let reply = unsafe { &*(reply_buf.as_ptr().cast::<ICMP_ECHO_REPLY>()) };
        let status = if count > 0 {
            reply.Status
        } else {
            // SAFETY: reads the thread's last error.
            unsafe { GetLastError() }
        };
        let addr = Ipv4Addr::from(reply.Address.to_ne_bytes());
        let responder = (!addr.is_unspecified()).then_some(addr);

        let outcome = match status {
            IP_SUCCESS => Outcome::Reached,
            IP_TTL_EXPIRED_TRANSIT => Outcome::Hop,
            IP_PACKET_TOO_BIG => Outcome::TooBig(None),
            IP_DEST_NET_UNREACHABLE => Outcome::Unreachable(0),
            IP_DEST_HOST_UNREACHABLE => Outcome::Unreachable(1),
            IP_DEST_PROT_UNREACHABLE => Outcome::Unreachable(2),
            IP_DEST_PORT_UNREACHABLE => Outcome::Unreachable(3),
            IP_DEST_PROHIBITED => Outcome::Unreachable(13),
            _ => return Ok(spec.timed_out()),
        };
        Ok(spec.result(responder, outcome, Some(rtt)))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod imp {
    use super::{ProbeError, ProbeResult, ProbeSpec};

    pub fn method() -> String {
        "unsupported".to_string()
    }

    pub fn probe(_spec: &ProbeSpec) -> Result<ProbeResult, ProbeError> {
        Err(ProbeError::Setup(
            "traceroute is not supported on this OS".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_len_subtracts_headers() {
        let spec = ProbeSpec {
            dst: Ipv4Addr::LOCALHOST,
            ttl: 1,
            ident: 1,
            seq: 1,
            size: 60,
            df: false,
            timeout: Duration::from_millis(10),
        };
        assert_eq!(spec.payload_len(), 32);
        assert_eq!(ProbeSpec { size: 10, ..spec }.payload_len(), 0);
    }
}

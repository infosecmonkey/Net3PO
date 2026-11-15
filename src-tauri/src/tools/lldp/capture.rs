//! Live capture through a user-installed libpcap (macOS, Linux) or Npcap
//! (Windows), loaded at run time. Nothing is linked or bundled: without the
//! library the app runs normally and this module explains what to install.
//!
//! The library is only loaded from system locations (the Npcap folder under
//! System32 on Windows, the system library paths elsewhere), never from the
//! app folder or the working directory.

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_uint, c_void};
use std::ptr;

use libloading::Library;

const ERRBUF_SIZE: usize = 256;
/// Bytes captured per frame; discovery frames are well under this.
pub const SNAPLEN: c_int = 4096;
/// Read timeout so the loop can check for Stop.
const READ_TIMEOUT_MS: c_int = 250;
/// Kernel filter: LLDP by EtherType, CDP by its multicast address.
pub const FILTER: &str = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc";

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut c_void,
    flags: c_uint,
}

/// `struct timeval` is two `long`s on Windows and Linux; on macOS it is a
/// 64-bit seconds field and a 32-bit microseconds field padded to 16 bytes,
/// so the same layout puts `caplen` at the right offset everywhere. Only
/// `caplen` is read.
#[repr(C)]
struct PktHdr {
    ts_sec: c_long,
    ts_usec: c_long,
    caplen: u32,
    len: u32,
}

#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut c_void,
}

type FindAllDevs = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type FreeAllDevs = unsafe extern "C" fn(*mut PcapIf);
type OpenLive =
    unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void;
type Compile =
    unsafe extern "C" fn(*mut c_void, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type SetFilter = unsafe extern "C" fn(*mut c_void, *mut BpfProgram) -> c_int;
type FreeCode = unsafe extern "C" fn(*mut BpfProgram);
type NextEx = unsafe extern "C" fn(*mut c_void, *mut *mut PktHdr, *mut *const u8) -> c_int;
type GetErr = unsafe extern "C" fn(*mut c_void) -> *mut c_char;
type Close = unsafe extern "C" fn(*mut c_void);
type Datalink = unsafe extern "C" fn(*mut c_void) -> c_int;
type LibVersion = unsafe extern "C" fn() -> *const c_char;

/// The loaded library and the functions this tool uses.
pub struct Pcap {
    findalldevs: FindAllDevs,
    freealldevs: FreeAllDevs,
    open_live: OpenLive,
    compile: Compile,
    setfilter: SetFilter,
    freecode: FreeCode,
    next_ex: NextEx,
    geterr: GetErr,
    close: Close,
    datalink: Datalink,
    lib_version: LibVersion,
    /// Keeps the function pointers above valid.
    _lib: Library,
}

/// A capture interface as libpcap names it.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub name: String,
    pub description: String,
    pub loopback: bool,
    pub up: bool,
}

const PCAP_IF_LOOPBACK: c_uint = 0x1;
const PCAP_IF_UP: c_uint = 0x2;

/// What to install when the library is missing, per OS.
pub fn install_hint() -> &'static str {
    if cfg!(windows) {
        "Install Npcap from npcap.com (the free edition is fine). Leave \"Restrict Npcap driver's access to Administrators only\" unticked so capture works without running as admin."
    } else if cfg!(target_os = "macos") {
        "macOS includes libpcap, but it could not be loaded."
    } else {
        "Install libpcap with your package manager: sudo apt install libpcap0.8 (Debian, Ubuntu) or sudo dnf install libpcap (RHEL, Fedora)."
    }
}

/// What to change when opening an interface is refused, per OS.
pub fn permission_hint() -> String {
    if cfg!(windows) {
        "Npcap refused access. If it was installed with \"Restrict Npcap driver's access to Administrators only\", reinstall it with that option unticked.".into()
    } else if cfg!(target_os = "macos") {
        "macOS needs read access to /dev/bpf*. Install Wireshark and its \"ChmodBPF\" package (it adds your user to the access_bpf group), then log out and back in. Net3PO does not need to run as root.".into()
    } else {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<path to omnipacket>".into());
        format!(
            "Capturing needs CAP_NET_RAW. Grant only that capability to the app binary:\n  sudo setcap cap_net_raw,cap_net_admin=eip {exe}\nNet3PO does not need to run as root."
        )
    }
}

fn candidates() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let sys = std::path::Path::new(&root).join("System32");
        out.push(sys.join("Npcap").join("wpcap.dll"));
        // Legacy WinPcap installs wpcap.dll into System32 itself.
        out.push(sys.join("wpcap.dll"));
    } else if cfg!(target_os = "macos") {
        out.push("/usr/lib/libpcap.A.dylib".into());
        out.push("/usr/lib/libpcap.dylib".into());
    } else {
        for name in ["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"] {
            out.push(name.into());
        }
    }
    out
}

#[cfg(windows)]
fn open_lib(path: &std::path::Path) -> Result<Library, libloading::Error> {
    // Resolve wpcap.dll's own dependencies (Packet.dll) from its folder.
    const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;
    // SAFETY: loading a system DLL by absolute path; its initializers are
    // those of the installed Npcap/WinPcap.
    unsafe {
        libloading::os::windows::Library::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH)
            .map(Into::into)
    }
}

#[cfg(not(windows))]
fn open_lib(path: &std::path::Path) -> Result<Library, libloading::Error> {
    // SAFETY: loading the system libpcap; its initializers are libpcap's own.
    unsafe { Library::new(path) }
}

impl Pcap {
    /// Load libpcap/Npcap from the system, or explain how to install it.
    pub fn load() -> Result<Pcap, String> {
        let mut last = String::new();
        for path in candidates() {
            match open_lib(&path) {
                Ok(lib) => return Self::from_lib(lib),
                Err(e) => last = format!("{}: {e}", path.display()),
            }
        }
        Err(format!(
            "packet capture library not found ({last}). {}",
            install_hint()
        ))
    }

    fn from_lib(lib: Library) -> Result<Pcap, String> {
        // SAFETY: each symbol is looked up by its libpcap name and cast to the
        // C signature documented in pcap(3PCAP). The Library is stored in the
        // struct, so the pointers outlive every use.
        unsafe {
            macro_rules! sym {
                ($name:literal) => {
                    *lib.get($name)
                        .map_err(|e| format!("libpcap is missing a function: {e}"))?
                };
            }
            Ok(Pcap {
                findalldevs: sym!(b"pcap_findalldevs\0"),
                freealldevs: sym!(b"pcap_freealldevs\0"),
                open_live: sym!(b"pcap_open_live\0"),
                compile: sym!(b"pcap_compile\0"),
                setfilter: sym!(b"pcap_setfilter\0"),
                freecode: sym!(b"pcap_freecode\0"),
                next_ex: sym!(b"pcap_next_ex\0"),
                geterr: sym!(b"pcap_geterr\0"),
                close: sym!(b"pcap_close\0"),
                datalink: sym!(b"pcap_datalink\0"),
                lib_version: sym!(b"pcap_lib_version\0"),
                _lib: lib,
            })
        }
    }

    /// The library's version string, such as "libpcap version 1.10.4".
    pub fn version(&self) -> String {
        // SAFETY: returns a static NUL-terminated string.
        unsafe { cstr((self.lib_version)()) }
    }

    /// Interfaces libpcap can open.
    pub fn devices(&self) -> Result<Vec<Device>, String> {
        let mut err = [0 as c_char; ERRBUF_SIZE];
        let mut head: *mut PcapIf = ptr::null_mut();
        // SAFETY: libpcap fills `head` with a list we free below, and writes
        // at most PCAP_ERRBUF_SIZE bytes to `err`.
        unsafe {
            if (self.findalldevs)(&mut head, err.as_mut_ptr()) != 0 {
                return Err(cstr(err.as_ptr()));
            }
            let mut out = Vec::new();
            let mut cur = head;
            while !cur.is_null() && out.len() < 256 {
                let d = &*cur;
                out.push(Device {
                    name: cstr(d.name),
                    description: cstr(d.description),
                    loopback: d.flags & PCAP_IF_LOOPBACK != 0,
                    up: d.flags & PCAP_IF_UP != 0,
                });
                cur = d.next;
            }
            if !head.is_null() {
                (self.freealldevs)(head);
            }
            Ok(out)
        }
    }

    /// Open an interface for discovery frames. Promiscuous mode is on because
    /// some NICs drop the reserved multicast addresses otherwise.
    pub fn open(&self, device: &str) -> Result<Handle<'_>, String> {
        let dev = CString::new(device).map_err(|_| "bad interface name".to_string())?;
        let mut err = [0 as c_char; ERRBUF_SIZE];
        // SAFETY: valid C string and error buffer; a null return is checked.
        let p = unsafe {
            (self.open_live)(dev.as_ptr(), SNAPLEN, 1, READ_TIMEOUT_MS, err.as_mut_ptr())
        };
        if p.is_null() {
            // SAFETY: libpcap wrote a NUL-terminated message into `err`.
            return Err(open_error(&unsafe { cstr(err.as_ptr()) }));
        }
        let h = Handle { pcap: self, p };
        h.set_filter(FILTER)?;
        Ok(h)
    }
}

/// Explain an open failure, adding the privilege fix when that is the cause.
pub fn open_error(msg: &str) -> String {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("permission")
        || lower.contains("not permitted")
        || lower.contains("access is denied")
        || lower.contains("administrator")
    {
        format!("{msg}\n{}", permission_hint())
    } else {
        msg.to_string()
    }
}

/// An open capture.
pub struct Handle<'a> {
    pcap: &'a Pcap,
    p: *mut c_void,
}

/// One read attempt.
pub enum Next<'b> {
    Frame(&'b [u8]),
    Timeout,
}

impl Handle<'_> {
    fn err(&self) -> String {
        // SAFETY: `p` is open; pcap_geterr returns a NUL-terminated buffer.
        unsafe { cstr((self.pcap.geterr)(self.p)) }
    }

    fn set_filter(&self, expr: &str) -> Result<(), String> {
        let c = CString::new(expr).map_err(|_| "bad filter".to_string())?;
        let mut prog = BpfProgram {
            bf_len: 0,
            bf_insns: ptr::null_mut(),
        };
        // SAFETY: `p` is open; the program is freed after setfilter copies it.
        unsafe {
            if (self.pcap.compile)(self.p, &mut prog, c.as_ptr(), 1, 0xffff_ffff) != 0 {
                return Err(format!("capture filter: {}", self.err()));
            }
            let r = (self.pcap.setfilter)(self.p, &mut prog);
            (self.pcap.freecode)(&mut prog);
            if r != 0 {
                return Err(format!("capture filter: {}", self.err()));
            }
        }
        Ok(())
    }

    /// The link type (DLT), such as 1 for Ethernet.
    pub fn link(&self) -> i32 {
        // SAFETY: `p` is open.
        unsafe { (self.pcap.datalink)(self.p) }
    }

    /// Wait up to the read timeout for a frame.
    pub fn next(&mut self) -> Result<Next<'_>, String> {
        let mut hdr: *mut PktHdr = ptr::null_mut();
        let mut data: *const u8 = ptr::null();
        // SAFETY: `p` is open; on 1 libpcap sets both pointers to buffers that
        // stay valid until the next call, which the borrow on `self` enforces.
        unsafe {
            match (self.pcap.next_ex)(self.p, &mut hdr, &mut data) {
                1 if !hdr.is_null() && !data.is_null() => {
                    let len = ((*hdr).caplen as usize).min(SNAPLEN as usize);
                    Ok(Next::Frame(std::slice::from_raw_parts(data, len)))
                }
                0 | 1 => Ok(Next::Timeout),
                _ => Err(self.err()),
            }
        }
    }
}

impl Drop for Handle<'_> {
    fn drop(&mut self) {
        // SAFETY: `p` was returned by pcap_open_live and is closed once.
        unsafe { (self.pcap.close)(self.p) }
    }
}

/// Copy a C string, treating null as empty.
///
/// SAFETY: `p` must be null or point to a NUL-terminated string.
unsafe fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: guaranteed by the caller.
    unsafe { CStr::from_ptr(p) }
        .to_string_lossy()
        .chars()
        .take(1024)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_name_the_fix() {
        let e = open_error("socket: Operation not permitted");
        assert!(e.contains("Operation not permitted"));
        assert!(e.lines().count() > 1);
        assert_eq!(open_error("no such device exists"), "no such device exists");
    }

    /// Manual: LLDP_LIVE_IF=en0 cargo test -- --ignored live_listen --nocapture
    #[test]
    #[ignore]
    fn live_listen() {
        let dev = std::env::var("LLDP_LIVE_IF").expect("set LLDP_LIVE_IF");
        let secs: u64 = std::env::var("LLDP_LIVE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(65);
        let p = Pcap::load().unwrap();
        println!("{}", p.version());
        let mut h = p.open(&dev).unwrap();
        println!("link type {}", h.link());
        let link = h.link();
        let start = std::time::Instant::now();
        let mut n = 0;
        while start.elapsed().as_secs() < secs {
            if let Next::Frame(f) = h.next().unwrap() {
                n += 1;
                match super::super::core::find(link, f) {
                    Some(found) => println!("{:#?}", super::super::core::decode(&found)),
                    None => println!("frame not decoded: {} bytes", f.len()),
                }
            }
        }
        println!("{n} frames");
    }

    /// Loading and listing must not crash on any CI runner, whether or not
    /// libpcap is present. macOS always ships it.
    #[test]
    fn loads_when_present() {
        match Pcap::load() {
            Ok(p) => {
                assert!(
                    p.version().to_lowercase().contains("pcap"),
                    "{}",
                    p.version()
                );
                let _ = p.devices();
            }
            Err(e) => {
                // macOS always ships libpcap, so only other systems may lack it.
                assert!(
                    !cfg!(target_os = "macos") && e.contains("not found"),
                    "unexpected load failure: {e}"
                );
            }
        }
    }
}

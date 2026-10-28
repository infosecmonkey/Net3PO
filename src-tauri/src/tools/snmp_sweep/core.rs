//! Pure helpers for the SNMP sweep: the identity OIDs it probes and octet-string
//! rendering. Host enumeration is reused from the port scanner, and SNMP I/O is
//! in `commands.rs`.

/// sysDescr, sysName, sysObjectID parents (the `.0` instance is fetched).
pub const SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1];
pub const SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5];
pub const SYS_OBJECT_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2];

/// Render a printable octet string as text, otherwise as spaced hex bytes.
pub fn render_octets(bytes: &[u8]) -> String {
    let printable = !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| *b == b'\t' || *b == b'\n' || *b == b'\r' || (0x20..=0x7e).contains(b));
    if printable {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_text() {
        assert_eq!(render_octets(b"FortiGate-60F"), "FortiGate-60F");
    }

    #[test]
    fn binary_as_hex() {
        assert_eq!(render_octets(&[0x00, 0x1b, 0x44, 0xff]), "00 1b 44 ff");
    }

    #[test]
    fn empty_is_empty() {
        assert_eq!(render_octets(&[]), "");
    }
}

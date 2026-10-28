//! Pure MAC vendor lookup logic. No Tauri types and no embedded data, so it can
//! be unit tested in isolation. The IEEE registry CSV is parsed into a
//! longest-prefix lookup across the MA-L (/24), MA-M (/28), and MA-S (/36)
//! assignment blocks.

use std::collections::HashMap;

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MacError {
    #[error("enter a MAC address")]
    Empty,
    #[error("'{0}' is not a hex digit")]
    BadChar(char),
    #[error("MAC must be whole octets (an even number of hex digits)")]
    OddLength,
    #[error("need at least 3 octets (24 bits) to look up a vendor")]
    TooShort,
    #[error("too many octets (maximum 8)")]
    TooLong,
}

/// One IEEE assignment: the prefix value right-aligned, its bit length, and the
/// organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub value: u64,
    pub bits: u8,
    pub org: String,
}

/// Longest-prefix lookup table over the three assignment block sizes.
#[derive(Debug, Default)]
pub struct Database {
    map24: HashMap<u32, String>,
    map28: HashMap<u32, String>,
    map36: HashMap<u64, String>,
}

/// Counts per block, for showing dataset coverage in the UI.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DbStats {
    pub total: usize,
    pub ma_l: usize,
    pub ma_m: usize,
    pub ma_s: usize,
}

/// Result of describing a MAC address.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MacInfo {
    /// Canonical colon form of the octets provided, uppercase.
    pub normalized: String,
    /// First three octets (the classic OUI).
    pub oui: String,
    /// The matched assignment prefix in hex, when a vendor was found.
    pub prefix: Option<String>,
    pub vendor: Option<String>,
    /// Assignment block: MA-L, MA-M, or MA-S.
    pub block: Option<String>,
    pub is_multicast: bool,
    pub is_locally_administered: bool,
}

/// Parse a MAC address in any common separator style into octets.
pub fn parse_mac(input: &str) -> Result<Vec<u8>, MacError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(MacError::Empty);
    }
    let mut hex = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        match c {
            ':' | '-' | '.' | ' ' => {}
            h if h.is_ascii_hexdigit() => hex.push(h),
            other => return Err(MacError::BadChar(other)),
        }
    }
    if hex.is_empty() {
        return Err(MacError::Empty);
    }
    if !hex.len().is_multiple_of(2) {
        return Err(MacError::OddLength);
    }
    let n = hex.len() / 2;
    if n < 3 {
        return Err(MacError::TooShort);
    }
    if n > 8 {
        return Err(MacError::TooLong);
    }
    let bytes = (0..n)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("validated hex"))
        .collect();
    Ok(bytes)
}

fn key24(b: &[u8]) -> u32 {
    (b[0] as u32) << 16 | (b[1] as u32) << 8 | (b[2] as u32)
}

fn key28(b: &[u8]) -> u32 {
    (b[0] as u32) << 20 | (b[1] as u32) << 12 | (b[2] as u32) << 4 | (b[3] as u32) >> 4
}

fn key36(b: &[u8]) -> u64 {
    (b[0] as u64) << 28
        | (b[1] as u64) << 20
        | (b[2] as u64) << 12
        | (b[3] as u64) << 4
        | (b[4] as u64) >> 4
}

impl Database {
    pub fn from_entries(entries: Vec<Entry>) -> Self {
        let mut db = Database::default();
        for e in entries {
            match e.bits {
                24 => {
                    db.map24.insert(e.value as u32, e.org);
                }
                28 => {
                    db.map28.insert(e.value as u32, e.org);
                }
                36 => {
                    db.map36.insert(e.value, e.org);
                }
                _ => {}
            }
        }
        db
    }

    pub fn parse(csv: &str) -> Self {
        Database::from_entries(parse_entries(csv))
    }

    pub fn stats(&self) -> DbStats {
        DbStats {
            ma_l: self.map24.len(),
            ma_m: self.map28.len(),
            ma_s: self.map36.len(),
            total: self.map24.len() + self.map28.len() + self.map36.len(),
        }
    }

    /// Longest-prefix lookup: try /36, then /28, then /24. Returns the vendor
    /// and the matched prefix bit length.
    pub fn lookup(&self, bytes: &[u8]) -> Option<(String, u8)> {
        if bytes.len() >= 5
            && let Some(org) = self.map36.get(&key36(bytes))
        {
            return Some((org.clone(), 36));
        }
        if bytes.len() >= 4
            && let Some(org) = self.map28.get(&key28(bytes))
        {
            return Some((org.clone(), 28));
        }
        if bytes.len() >= 3
            && let Some(org) = self.map24.get(&key24(bytes))
        {
            return Some((org.clone(), 24));
        }
        None
    }
}

/// Parse the IEEE registry CSV (MA-L, MA-M, MA-S rows) into entries.
pub fn parse_entries(csv: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    for line in csv.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let fields = parse_csv_fields(line);
        if fields.len() < 3 {
            continue;
        }
        let bits = match fields[0].trim() {
            "MA-L" => 24,
            "MA-M" => 28,
            "MA-S" => 36,
            _ => continue, // header row or anything unexpected
        };
        let assignment = fields[1].trim();
        let org = fields[2].trim();
        if assignment.is_empty() || org.is_empty() {
            continue;
        }
        let Ok(value) = u64::from_str_radix(assignment, 16) else {
            continue;
        };
        entries.push(Entry {
            value,
            bits,
            org: org.to_string(),
        });
    }
    entries
}

/// Minimal CSV line parser handling double-quoted fields with "" escapes and
/// embedded commas. Enough for the IEEE registry format.
fn parse_csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => fields.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
    }
    fields.push(cur);
    fields
}

fn block_name(bits: u8) -> &'static str {
    match bits {
        24 => "MA-L",
        28 => "MA-M",
        36 => "MA-S",
        _ => "?",
    }
}

fn prefix_hex(bytes: &[u8], bits: u8) -> String {
    match bits {
        24 => format!("{:06X}", key24(bytes)),
        28 => format!("{:07X}", key28(bytes)),
        36 => format!("{:09X}", key36(bytes)),
        _ => String::new(),
    }
}

/// Describe a MAC: normalize it, classify the address bits, and look up the
/// vendor.
pub fn describe(bytes: &[u8], db: &Database) -> MacInfo {
    let normalized = bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let oui = bytes
        .iter()
        .take(3)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");

    let (vendor, block, prefix) = match db.lookup(bytes) {
        Some((org, bits)) => (
            Some(org),
            Some(block_name(bits).to_string()),
            Some(prefix_hex(bytes, bits)),
        ),
        None => (None, None, None),
    };

    MacInfo {
        normalized,
        oui,
        prefix,
        vendor,
        block,
        is_multicast: bytes[0] & 0x01 != 0,
        is_locally_administered: bytes[0] & 0x02 != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Registry,Assignment,Organization Name,Organization Address\n\
MA-L,00000C,\"Cisco Systems, Inc\",170 West Tasman Dr.\n\
MA-L,8C1F64,IEEE Registration Authority,Piscataway\n\
MA-M,8C1F64D,Small Vendor M,Somewhere\n\
MA-L,70B3D5,IEEE Registration Authority,Piscataway\n\
MA-S,70B3D5E1F,Small Vendor S,Elsewhere\n";

    fn db() -> Database {
        Database::parse(SAMPLE)
    }

    #[test]
    fn parses_separators() {
        let want = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(parse_mac("AA:BB:CC:DD:EE:FF").unwrap(), want);
        assert_eq!(parse_mac("aa-bb-cc-dd-ee-ff").unwrap(), want);
        assert_eq!(parse_mac("aabb.ccdd.eeff").unwrap(), want);
        assert_eq!(parse_mac("AABBCCDDEEFF").unwrap(), want);
    }

    #[test]
    fn parse_errors() {
        assert_eq!(parse_mac("  ").unwrap_err(), MacError::Empty);
        assert_eq!(parse_mac("zz:11:22").unwrap_err(), MacError::BadChar('z'));
        assert_eq!(parse_mac("00:11:2").unwrap_err(), MacError::OddLength);
        assert_eq!(parse_mac("00:11").unwrap_err(), MacError::TooShort);
        assert_eq!(
            parse_mac("00112233445566778899").unwrap_err(),
            MacError::TooLong
        );
    }

    #[test]
    fn csv_handles_quoted_comma() {
        let entries = parse_entries(SAMPLE);
        let cisco = entries.iter().find(|e| e.value == 0x00000C).unwrap();
        assert_eq!(cisco.org, "Cisco Systems, Inc");
        assert_eq!(cisco.bits, 24);
    }

    #[test]
    fn lookup_ma_l() {
        let info = describe(&parse_mac("00:00:0C:12:34:56").unwrap(), &db());
        assert_eq!(info.vendor.as_deref(), Some("Cisco Systems, Inc"));
        assert_eq!(info.block.as_deref(), Some("MA-L"));
        assert_eq!(info.prefix.as_deref(), Some("00000C"));
        assert_eq!(info.oui, "00:00:0C");
    }

    #[test]
    fn lookup_ma_m_beats_parent() {
        // 8C:1F:64 is held by IEEE for subdivision; the /28 is the real vendor.
        let info = describe(&parse_mac("8C:1F:64:D5:00:00").unwrap(), &db());
        assert_eq!(info.vendor.as_deref(), Some("Small Vendor M"));
        assert_eq!(info.block.as_deref(), Some("MA-M"));
        assert_eq!(info.prefix.as_deref(), Some("8C1F64D"));
    }

    #[test]
    fn lookup_ma_s_beats_parent() {
        let info = describe(&parse_mac("70:B3:D5:E1:F0:00").unwrap(), &db());
        assert_eq!(info.vendor.as_deref(), Some("Small Vendor S"));
        assert_eq!(info.block.as_deref(), Some("MA-S"));
        assert_eq!(info.prefix.as_deref(), Some("70B3D5E1F"));
    }

    #[test]
    fn ma_m_falls_back_to_parent_when_outside_subblock() {
        // 8C:1F:64 with a /28 nibble that is not the assigned one resolves to
        // the MA-L parent.
        let info = describe(&parse_mac("8C:1F:64:00:00:00").unwrap(), &db());
        assert_eq!(info.vendor.as_deref(), Some("IEEE Registration Authority"));
        assert_eq!(info.block.as_deref(), Some("MA-L"));
    }

    #[test]
    fn unknown_vendor() {
        let info = describe(&parse_mac("DE:AD:BE:EF:00:11").unwrap(), &db());
        assert_eq!(info.vendor, None);
        assert_eq!(info.block, None);
        assert_eq!(info.prefix, None);
    }

    #[test]
    fn address_flags() {
        // 01:... has the multicast bit set.
        let mc = describe(&parse_mac("01:00:5E:00:00:01").unwrap(), &db());
        assert!(mc.is_multicast);
        // AA = 1010_1010, bit 1 set -> locally administered, bit 0 clear.
        let la = describe(&parse_mac("AA:BB:CC:DD:EE:FF").unwrap(), &db());
        assert!(la.is_locally_administered);
        assert!(!la.is_multicast);
    }

    #[test]
    fn oui_only_lookup() {
        // Three octets is enough for a /24 match.
        let info = describe(&parse_mac("00:00:0C").unwrap(), &db());
        assert_eq!(info.vendor.as_deref(), Some("Cisco Systems, Inc"));
        assert_eq!(info.normalized, "00:00:0C");
    }

    #[test]
    fn stats_count_per_block() {
        let s = db().stats();
        assert_eq!(s.ma_l, 3);
        assert_eq!(s.ma_m, 1);
        assert_eq!(s.ma_s, 1);
        assert_eq!(s.total, 5);
    }
}

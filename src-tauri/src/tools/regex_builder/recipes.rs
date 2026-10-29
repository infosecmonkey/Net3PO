//! Ready-made expressions for network and log data, ported from macGREP and
//! extended for network engineering work.
//!
//! Every recipe sticks to syntax both engines accept, and uses POSIX classes
//! like `[[:space:]]` rather than `\s` so it also pastes into `grep -E`. Each
//! one carries examples it must match and strings it must not, checked by the
//! unit tests below on both engines.

use serde::Serialize;

/// One ready-made expression.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipe {
    /// Stable identifier, unique across the library.
    pub id: &'static str,
    /// Group heading shown in the picker.
    pub group: &'static str,
    pub label: &'static str,
    pub pattern: &'static str,
    pub help: &'static str,
    /// Strings the pattern matches in full. The first is shown as an example.
    pub examples: &'static [&'static str],
    /// Strings the pattern must not match anywhere. Test data only.
    #[serde(skip)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub non_matches: &'static [&'static str],
}

// Building blocks, as macros so `concat!` can assemble them at compile time.

/// One IPv4 octet, 0 to 255.
macro_rules! octet {
    () => {
        r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    };
}

/// A strict dotted-quad IPv4 address.
macro_rules! ipv4 {
    () => {
        concat!(r"\b(", octet!(), r"\.){3}", octet!(), r"\b")
    };
}

/// An IPv4 prefix length, /0 to /32.
macro_rules! v4_prefix {
    () => {
        r"/(3[0-2]|[12]?[0-9])\b"
    };
}

/// Octet values at the boundary of a contiguous subnet mask.
macro_rules! mask_octet {
    () => {
        r"(255|254|252|248|240|224|192|128|0)"
    };
}

/// A contiguous subnet mask such as 255.255.255.0 or 255.255.240.0.
macro_rules! subnet_mask {
    () => {
        concat!(
            r"\b(255\.255\.255\.",
            mask_octet!(),
            r"|255\.255\.",
            mask_octet!(),
            r"\.0|255\.",
            mask_octet!(),
            r"\.0\.0|",
            mask_octet!(),
            r"\.0\.0\.0)\b"
        )
    };
}

/// Octet values at the boundary of a wildcard (inverse) mask.
macro_rules! wildcard_octet {
    () => {
        r"(255|127|63|31|15|7|3|1|0)"
    };
}

/// A TCP/UDP port, 1 to 65535.
macro_rules! port {
    () => {
        r"(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})"
    };
}

/// A full or `::` compressed IPv6 address. Alternatives that consume trailing
/// groups come first, so leftmost-first engines agree with grep's
/// leftmost-longest rule.
macro_rules! ipv6 {
    () => {
        concat!(
            r"(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}",
            r"|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}",
            r"|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}",
            r"|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}",
            r"|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}",
            r"|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}",
            r"|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6}",
            r"|([0-9A-Fa-f]{1,4}:){1,7}:",
            r"|:((:[0-9A-Fa-f]{1,4}){1,7}|:))"
        )
    };
}

const IPV4: &str = "IPv4";
const IPV6_L2: &str = "IPv6 and L2";
const HOSTS: &str = "Hosts and URLs";
const LOGS: &str = "Logs";
const GENERAL: &str = "General";

/// The recipe library, in display order.
pub const RECIPES: &[Recipe] = &[
    // --- IPv4 -------------------------------------------------------------
    Recipe {
        id: "ipv4",
        group: IPV4,
        label: "IPv4 address",
        pattern: ipv4!(),
        help: "Dotted quad, each octet 0 to 255",
        examples: &["192.168.1.20", "10.0.0.7", "255.255.255.255"],
        non_matches: &["256.1.1.1", "10.10.10.999", "1.2.3"],
    },
    Recipe {
        id: "ipv4-loose",
        group: IPV4,
        label: "IPv4 (loose)",
        pattern: r"\b([0-9]{1,3}\.){3}[0-9]{1,3}\b",
        help: "Four groups of 1 to 3 digits. Easier to read, accepts 999",
        examples: &["10.0.0.7", "999.1.1.1"],
        non_matches: &["1.2.3", "1234.1.1.1"],
    },
    Recipe {
        id: "ipv4-cidr",
        group: IPV4,
        label: "IPv4/CIDR",
        pattern: concat!(ipv4!(), v4_prefix!()),
        help: "Address with prefix length, /0 to /32",
        examples: &["10.0.0.0/8", "192.168.1.0/24", "0.0.0.0/0"],
        non_matches: &["10.0.0.0/33", "10.0.0.0"],
    },
    Recipe {
        id: "ipv4-mask",
        group: IPV4,
        label: "IPv4 + subnet mask",
        pattern: concat!(ipv4!(), r"[[:space:]]+", subnet_mask!()),
        help: "Address then mask, as in Cisco and FortiOS config",
        examples: &["10.10.10.1 255.255.255.0", "192.168.100.2 255.255.255.252"],
        non_matches: &["10.10.10.1 255.255.255.1", "10.10.10.1 0.0.0.255"],
    },
    Recipe {
        id: "ipv4-mask-or-cidr",
        group: IPV4,
        label: "IPv4 + mask or CIDR",
        pattern: concat!(
            ipv4!(),
            r"([[:space:]]+",
            subnet_mask!(),
            "|",
            v4_prefix!(),
            ")"
        ),
        help: "Address with either a mask or a /n prefix",
        examples: &["10.10.10.0 255.255.255.0", "10.10.10.0/24"],
        non_matches: &["10.10.10.0"],
    },
    Recipe {
        id: "subnet-mask",
        group: IPV4,
        label: "Subnet mask",
        pattern: subnet_mask!(),
        help: "Contiguous mask only",
        examples: &["255.255.255.0", "255.255.240.0", "255.0.0.0"],
        non_matches: &["255.255.255.1", "255.0.255.0", "255.255.253.0"],
    },
    Recipe {
        id: "wildcard-mask",
        group: IPV4,
        label: "Wildcard mask",
        pattern: concat!(
            r"\b(0\.0\.0\.",
            wildcard_octet!(),
            r"|0\.0\.",
            wildcard_octet!(),
            r"\.255|0\.",
            wildcard_octet!(),
            r"\.255\.255|",
            wildcard_octet!(),
            r"\.255\.255\.255)\b"
        ),
        help: "Inverse mask used in Cisco ACLs and OSPF",
        examples: &["0.0.0.255", "0.0.15.255", "0.0.255.255"],
        non_matches: &["0.0.255.0", "0.0.0.254"],
    },
    Recipe {
        id: "ipv4-port",
        group: IPV4,
        label: "IPv4:port",
        pattern: concat!(ipv4!(), ":", port!(), r"\b"),
        help: "Address and port, port 1 to 65535",
        examples: &["192.168.1.1:8080", "203.0.113.10:443"],
        non_matches: &["192.168.1.1:65536", "192.168.1.1:0"],
    },
    Recipe {
        id: "private-ipv4",
        group: IPV4,
        label: "Private IPv4 (RFC 1918)",
        pattern: concat!(
            r"\b(10\.(",
            octet!(),
            r"\.){2}",
            octet!(),
            r"|172\.(1[6-9]|2[0-9]|3[01])\.",
            octet!(),
            r"\.",
            octet!(),
            r"|192\.168\.",
            octet!(),
            r"\.",
            octet!(),
            r")\b"
        ),
        help: "10/8, 172.16/12, 192.168/16",
        examples: &["10.1.2.3", "172.31.255.1", "192.168.0.1"],
        non_matches: &["172.32.0.1", "11.0.0.1", "192.169.0.1"],
    },
    Recipe {
        id: "cgnat-ipv4",
        group: IPV4,
        label: "CGNAT (RFC 6598)",
        pattern: concat!(
            r"\b100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.",
            octet!(),
            r"\.",
            octet!(),
            r"\b"
        ),
        help: "Shared address space 100.64.0.0/10",
        examples: &["100.64.0.1", "100.127.255.254"],
        non_matches: &["100.63.0.1", "100.128.0.1"],
    },
    Recipe {
        id: "loopback-linklocal",
        group: IPV4,
        label: "Loopback / link-local",
        pattern: concat!(
            r"\b(127\.(",
            octet!(),
            r"\.){2}",
            octet!(),
            r"|169\.254\.",
            octet!(),
            r"\.",
            octet!(),
            r")\b"
        ),
        help: "127/8 and 169.254/16 (APIPA)",
        examples: &["127.0.0.1", "169.254.10.20"],
        non_matches: &["128.0.0.1", "169.253.1.1"],
    },
    Recipe {
        id: "multicast-ipv4",
        group: IPV4,
        label: "Multicast IPv4",
        pattern: concat!(
            r"\b(22[4-9]|23[0-9])\.(",
            octet!(),
            r"\.){2}",
            octet!(),
            r"\b"
        ),
        help: "224.0.0.0 to 239.255.255.255",
        examples: &["224.0.0.5", "239.1.1.5"],
        non_matches: &["223.255.255.255", "240.0.0.1"],
    },
    Recipe {
        id: "default-route",
        group: IPV4,
        label: "Default route",
        pattern: r"\b0\.0\.0\.0([[:space:]]+0\.0\.0\.0|/0)\b",
        help: "0.0.0.0 0.0.0.0 or 0.0.0.0/0",
        examples: &["0.0.0.0 0.0.0.0", "0.0.0.0/0"],
        non_matches: &["0.0.0.0/8", "10.0.0.0/0"],
    },
    Recipe {
        id: "port",
        group: IPV4,
        label: "Port number",
        pattern: concat!(r"\b", port!(), r"\b"),
        help: "1 to 65535",
        examples: &["22", "443", "65535"],
        non_matches: &["65536", "0", "70000"],
    },
    // --- IPv6 and L2 ------------------------------------------------------
    Recipe {
        id: "ipv6",
        group: IPV6_L2,
        label: "IPv6 address",
        pattern: ipv6!(),
        help: "Full or :: compressed",
        examples: &[
            "2001:db8::1",
            "fe80::1",
            "::1",
            "2001:0db8:0000:0000:0000:ff00:0042:8329",
        ],
        non_matches: &["12:30", "00:1a:2b:3c:4d:5e"],
    },
    Recipe {
        id: "ipv6-cidr",
        group: IPV6_L2,
        label: "IPv6 CIDR",
        pattern: concat!(ipv6!(), r"/(12[0-8]|1[01][0-9]|[1-9]?[0-9])\b"),
        help: "IPv6 address with prefix length, /0 to /128",
        examples: &["2001:db8::/32", "fe80::/10", "2001:db8:10::1/128"],
        non_matches: &["2001:db8::/129", "2001:db8::1"],
    },
    Recipe {
        id: "ipv6-linklocal",
        group: IPV6_L2,
        label: "IPv6 link-local",
        pattern: r"\b[Ff][Ee][89ABab][0-9A-Fa-f]:(:?[0-9A-Fa-f]{1,4}){0,7}(%[A-Za-z0-9._-]+)?",
        help: "fe80::/10, with optional %zone",
        examples: &["fe80::1", "fe80::20c:29ff:fe12:3456%eth0"],
        non_matches: &["fec0::1", "2001:db8::1"],
    },
    Recipe {
        id: "mac",
        group: IPV6_L2,
        label: "MAC address",
        pattern: r"\b(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})\b",
        help: "Colon, dash or Cisco dotted format",
        examples: &["00:1a:2b:3c:4d:5e", "00-1A-2B-3C-4D-5E", "0050.56ab.cdef"],
        non_matches: &["00:1a:2b:3c:4d", "0050.56ab"],
    },
    Recipe {
        id: "vlan-id",
        group: IPV6_L2,
        label: "VLAN ID",
        pattern: r"\b(409[0-4]|40[0-8][0-9]|[1-3][0-9]{3}|[1-9][0-9]{0,2})\b",
        help: "1 to 4094",
        examples: &["1", "100", "4094"],
        non_matches: &["0", "4095", "5000"],
    },
    Recipe {
        id: "interface",
        group: IPV6_L2,
        label: "Interface name",
        pattern: r"\b(GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|HundredGigE|FastEthernet|Ethernet|Port-channel|Vlan|Loopback|Tunnel|Gi|Te|Fa|Eth|Et|Po|Lo|Tu)[0-9]+(/[0-9]+)*(\.[0-9]+)?\b",
        help: "Cisco and Arista style, with optional subinterface",
        examples: &[
            "GigabitEthernet0/1",
            "Gi1/0/24",
            "Te1/1/1.100",
            "Port-channel10",
            "Vlan10",
            "Ethernet49/1",
        ],
        non_matches: &["Giga", "port1"],
    },
    // --- Hosts and URLs ---------------------------------------------------
    Recipe {
        id: "fqdn",
        group: HOSTS,
        label: "Hostname / FQDN",
        pattern: r"\b([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b",
        help: "Dotted name with a letters-only TLD",
        examples: &["core-sw-01.example.com", "www.example.org"],
        non_matches: &["localhost", "10.10.10.1"],
    },
    Recipe {
        id: "url",
        group: HOSTS,
        label: "URL",
        pattern: r#"https?://[^[:space:]"'<>]+"#,
        help: "http or https URL up to whitespace or a quote",
        examples: &["https://api.example.com/v1", "http://10.0.0.1:8080/status"],
        non_matches: &["ftp://example.com", "example.com/path"],
    },
    Recipe {
        id: "email",
        group: HOSTS,
        label: "Email",
        pattern: r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        help: "Email address",
        examples: &["alice@example.com", "dev+billing@example.co.uk"],
        non_matches: &["alice@localhost", "@example.com"],
    },
    Recipe {
        id: "asn",
        group: HOSTS,
        label: "AS number",
        pattern: r"\bAS[[:space:]]?[0-9]{1,10}\b",
        help: "AS64512, AS 13335",
        examples: &["AS64512", "AS 13335"],
        non_matches: &["ASN", "BAS123"],
    },
    // --- Logs -------------------------------------------------------------
    Recipe {
        id: "syslog-pri",
        group: LOGS,
        label: "Syslog PRI",
        pattern: r"<(19[01]|1[0-8][0-9]|[1-9]?[0-9])>",
        help: "Priority header <0> to <191>. Group 1 is facility * 8 + severity",
        examples: &["<134>", "<0>", "<191>"],
        non_matches: &["<192>", "<01>", "<abc>"],
    },
    Recipe {
        id: "bsd-timestamp",
        group: LOGS,
        label: "Syslog timestamp (RFC 3164)",
        pattern: r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}\b",
        help: "Oct 29 08:14:02, or Oct  9 with a padded day",
        examples: &["Oct 29 08:14:02", "Oct  9 08:14:02"],
        non_matches: &["October 29 08:14:02", "Oct 29 8:14:02"],
    },
    Recipe {
        id: "iso-timestamp",
        group: LOGS,
        label: "ISO 8601 timestamp",
        pattern: r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:?[0-9]{2})?",
        help: "2026-10-29T08:14:02Z, with optional fraction and offset",
        examples: &[
            "2026-10-29T08:14:02Z",
            "2026-10-29 08:14:02",
            "2026-10-29T08:14:02.123-04:00",
        ],
        non_matches: &["2026-10-29", "08:14:02"],
    },
    Recipe {
        id: "cisco-mnemonic",
        group: LOGS,
        label: "Cisco log mnemonic",
        pattern: r"%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+",
        help: "%FACILITY-SEVERITY-MNEMONIC. Change [0-7] to [0-3] for errors and worse",
        examples: &["%LINK-3-UPDOWN", "%SYS-5-CONFIG_I"],
        non_matches: &["%LINK-8-UPDOWN", "LINK-3-UPDOWN"],
    },
    Recipe {
        id: "kv-pair",
        group: LOGS,
        label: "key=value pair",
        pattern: r#"\b([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|[^[:space:]"]+)"#,
        help: "FortiGate and other key=value logs. Group 1 is the key, group 2 the value",
        examples: &["srcip=10.10.10.25", r#"devname="FGT-HQ""#, "policyid=5"],
        non_matches: &["=5", "a = b"],
    },
    Recipe {
        id: "forti-src-dst",
        group: LOGS,
        label: "FortiGate srcip / dstip",
        pattern: concat!(r"\b(srcip|dstip|transip|tranip)=", ipv4!()),
        help: "Address fields in FortiGate traffic logs",
        examples: &["srcip=10.10.10.25", "dstip=8.8.8.8"],
        non_matches: &["srcport=51234", "srcip=10.10.10.999"],
    },
    Recipe {
        id: "forti-action",
        group: LOGS,
        label: "FortiGate action",
        pattern: r#"\baction="?(deny|accept|close|timeout|server-rst|client-rst|ip-conn|dns|blocked|passthrough)"?"#,
        help: "Traffic and UTM log action field",
        examples: &[r#"action="deny""#, "action=accept"],
        non_matches: &[r#"action="foo""#],
    },
    Recipe {
        id: "log-level",
        group: LOGS,
        label: "Log level",
        pattern: r"\b(EMERG|ALERT|CRIT(ICAL)?|ERR(OR)?|WARN(ING)?|NOTICE|INFO|DEBUG|FATAL)\b",
        help: "Common severity words. Turn on ignore case for lowercase logs",
        examples: &["ERROR", "WARNING", "CRIT"],
        non_matches: &["ERRORS", "information"],
    },
    Recipe {
        id: "http-error",
        group: LOGS,
        label: "HTTP status 4xx/5xx",
        pattern: r"\b[45][0-9]{2}\b",
        help: "Client or server error codes",
        examples: &["404", "502"],
        non_matches: &["200", "4040"],
    },
    // --- General ----------------------------------------------------------
    Recipe {
        id: "iso-date",
        group: GENERAL,
        label: "ISO date",
        pattern: r"\b[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])\b",
        help: "YYYY-MM-DD",
        examples: &["2026-10-29", "2026-01-01"],
        non_matches: &["2026-13-01", "2026-10-32"],
    },
    Recipe {
        id: "time",
        group: GENERAL,
        label: "Time",
        pattern: r"\b([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?\b",
        help: "HH:MM or HH:MM:SS, 24 hour",
        examples: &["08:14", "23:59:59"],
        non_matches: &["24:00", "8:14"],
    },
    Recipe {
        id: "number",
        group: GENERAL,
        label: "Number",
        pattern: r"-?[0-9]+(\.[0-9]+)?",
        help: "Integer or decimal",
        examples: &["42", "-3.14"],
        non_matches: &["abc"],
    },
    Recipe {
        id: "hex",
        group: GENERAL,
        label: "Hex value",
        pattern: r"\b0x[0-9A-Fa-f]+\b",
        help: "0x prefixed, such as an SNMP or register value",
        examples: &["0x1F", "0xdeadbeef"],
        non_matches: &["0x", "1F"],
    },
    Recipe {
        id: "uuid",
        group: GENERAL,
        label: "UUID",
        pattern: r"\b[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\b",
        help: "UUID / GUID",
        examples: &["5f1c2a9e-8b7d-4c3e-9f0a-1b2c3d4e5f60"],
        non_matches: &["5f1c2a9e-8b7d-4c3e-9f0a"],
    },
    Recipe {
        id: "quoted",
        group: GENERAL,
        label: "Quoted string",
        pattern: r#""[^"]*""#,
        help: "Double-quoted string",
        examples: &[r#""FGT-HQ""#, r#""""#],
        non_matches: &["no quotes"],
    },
    Recipe {
        id: "blank-line",
        group: GENERAL,
        label: "Blank line",
        pattern: r"^[ \t]*$",
        help: "Empty or whitespace-only line. Turn on multiline (m)",
        examples: &["", "   "],
        non_matches: &["x", "  x  "],
    },
];

/// The full recipe library, in display order.
pub fn recipes() -> &'static [Recipe] {
    RECIPES
}

#[cfg(test)]
mod tests {
    use super::super::core::{Engine, RegexFlags, test};
    use super::*;
    use std::collections::HashSet;

    const ENGINES: [Engine; 2] = [Engine::Standard, Engine::Pcre];

    #[test]
    fn ids_unique_and_fields_present() {
        let mut seen = HashSet::new();
        for r in RECIPES {
            assert!(seen.insert(r.id), "duplicate id {}", r.id);
            assert!(!r.label.is_empty() && !r.help.is_empty(), "{}", r.id);
            assert!(!r.examples.is_empty(), "{} has no examples", r.id);
        }
    }

    #[test]
    fn no_em_dashes_in_text() {
        for r in RECIPES {
            for s in [r.label, r.help, r.group] {
                assert!(!s.contains('\u{2014}'), "em dash in {}", r.id);
            }
        }
    }

    #[test]
    fn examples_match_in_full_on_both_engines() {
        let flags = RegexFlags::default();
        for r in RECIPES {
            for engine in ENGINES {
                for ex in r.examples {
                    let res = test(r.pattern, ex, &flags, engine)
                        .unwrap_or_else(|e| panic!("{} on {engine:?}: {e}", r.id));
                    assert!(
                        res.matches.iter().any(|m| m.value == *ex),
                        "{} on {engine:?} did not fully match {ex:?}, got {:?}",
                        r.id,
                        res.matches.iter().map(|m| &m.value).collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    #[test]
    fn non_matches_do_not_match_on_both_engines() {
        let flags = RegexFlags::default();
        for r in RECIPES {
            for engine in ENGINES {
                for bad in r.non_matches {
                    let res = test(r.pattern, bad, &flags, engine).unwrap();
                    assert_eq!(
                        res.total,
                        0,
                        "{} on {engine:?} matched {bad:?}: {:?}",
                        r.id,
                        res.matches.iter().map(|m| &m.value).collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    #[test]
    fn ipv4_finds_addresses_in_a_config_line() {
        let r = RECIPES.iter().find(|r| r.id == "ipv4").unwrap();
        let res = test(
            r.pattern,
            " ip address 10.10.10.1 255.255.255.0",
            &RegexFlags::default(),
            Engine::Standard,
        )
        .unwrap();
        let found: Vec<_> = res.matches.iter().map(|m| m.value.as_str()).collect();
        assert_eq!(found, ["10.10.10.1", "255.255.255.0"]);
    }
}

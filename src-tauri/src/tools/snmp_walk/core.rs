//! Pure SNMP-walk support: OID parsing, a name<->OID registry seeded with
//! common MIB-II names, and a pragmatic MIB-file parser that extracts OID
//! assignments for display translation. No network here; the live SNMP I/O is
//! in `commands.rs`.

use std::collections::HashMap;

use regex::Regex;

/// A name <-> OID registry. Seeded with MIB-II; extend by loading MIB files.
#[derive(Debug, Clone, Default)]
pub struct Mib {
    by_name: HashMap<String, Vec<u32>>,
    by_oid: HashMap<Vec<u32>, String>,
}

/// Common OID names so typical walks read sensibly out of the box.
const BUILTIN: &[(&str, &[u32])] = &[
    ("iso", &[1]),
    ("org", &[1, 3]),
    ("dod", &[1, 3, 6]),
    ("internet", &[1, 3, 6, 1]),
    ("directory", &[1, 3, 6, 1, 1]),
    ("mgmt", &[1, 3, 6, 1, 2]),
    ("mib-2", &[1, 3, 6, 1, 2, 1]),
    ("private", &[1, 3, 6, 1, 4]),
    ("enterprises", &[1, 3, 6, 1, 4, 1]),
    ("system", &[1, 3, 6, 1, 2, 1, 1]),
    ("sysDescr", &[1, 3, 6, 1, 2, 1, 1, 1]),
    ("sysObjectID", &[1, 3, 6, 1, 2, 1, 1, 2]),
    ("sysUpTime", &[1, 3, 6, 1, 2, 1, 1, 3]),
    ("sysContact", &[1, 3, 6, 1, 2, 1, 1, 4]),
    ("sysName", &[1, 3, 6, 1, 2, 1, 1, 5]),
    ("sysLocation", &[1, 3, 6, 1, 2, 1, 1, 6]),
    ("sysServices", &[1, 3, 6, 1, 2, 1, 1, 7]),
    ("interfaces", &[1, 3, 6, 1, 2, 1, 2]),
    ("ifNumber", &[1, 3, 6, 1, 2, 1, 2, 1]),
    ("ifTable", &[1, 3, 6, 1, 2, 1, 2, 2]),
    ("ifEntry", &[1, 3, 6, 1, 2, 1, 2, 2, 1]),
    ("ifIndex", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 1]),
    ("ifDescr", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2]),
    ("ifType", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 3]),
    ("ifMtu", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 4]),
    ("ifSpeed", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 5]),
    ("ifPhysAddress", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 6]),
    ("ifAdminStatus", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 7]),
    ("ifOperStatus", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 8]),
    ("ifInOctets", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 10]),
    ("ifInErrors", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 14]),
    ("ifOutOctets", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 16]),
    ("ifOutErrors", &[1, 3, 6, 1, 2, 1, 2, 2, 1, 20]),
    ("ip", &[1, 3, 6, 1, 2, 1, 4]),
    ("tcp", &[1, 3, 6, 1, 2, 1, 6]),
    ("udp", &[1, 3, 6, 1, 2, 1, 7]),
    ("snmp", &[1, 3, 6, 1, 2, 1, 11]),
    ("host", &[1, 3, 6, 1, 2, 1, 25]),
];

impl Mib {
    /// A registry seeded with the built-in common names.
    pub fn with_builtins() -> Self {
        let mut mib = Mib::default();
        for (name, oid) in BUILTIN {
            mib.insert(name, oid.to_vec());
        }
        mib
    }

    fn insert(&mut self, name: &str, oid: Vec<u32>) {
        self.by_name.insert(name.to_string(), oid.clone());
        // Keep the first (usually canonical) name for a given OID.
        self.by_oid.entry(oid).or_insert_with(|| name.to_string());
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    #[allow(dead_code)] // paired with len() to satisfy clippy::len_without_is_empty
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Render an OID using the longest known name prefix, e.g.
    /// `[1,3,6,1,2,1,1,1,0]` -> "sysDescr.0". Falls back to dotted numeric.
    pub fn translate(&self, oid: &[u32]) -> String {
        for len in (1..=oid.len()).rev() {
            if let Some(name) = self.by_oid.get(&oid[..len]) {
                if len == oid.len() {
                    return name.clone();
                }
                let suffix = oid[len..]
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(".");
                return format!("{name}.{suffix}");
            }
        }
        dotted(oid)
    }

    /// Resolve user input (dotted numeric, a name, or `name.suffix`) to an OID.
    pub fn resolve(&self, input: &str) -> Option<Vec<u32>> {
        let s = input.trim().trim_start_matches('.');
        if s.is_empty() {
            return None;
        }
        // All-numeric dotted form.
        if s.split('.').all(|p| p.parse::<u32>().is_ok()) {
            return s.split('.').map(|p| p.parse().ok()).collect();
        }
        // name, or name.<numeric suffix>.
        let mut parts = s.splitn(2, '.');
        let name = parts.next()?;
        let base = self.by_name.get(name)?.clone();
        match parts.next() {
            None => Some(base),
            Some(rest) => {
                let mut oid = base;
                for p in rest.split('.') {
                    oid.push(p.parse().ok()?);
                }
                Some(oid)
            }
        }
    }

    /// Parse MIB text and merge its OID assignments. Returns how many names were
    /// added. Resolution is iterative so out-of-order definitions still link.
    pub fn load_mib(&mut self, text: &str) -> usize {
        let mut pending = parse_mib(text);
        let mut added = 0;
        loop {
            let mut progressed = false;
            let mut still = Vec::new();
            for def in pending {
                match self.resolve_tokens(&def.tokens) {
                    Some(oid) => {
                        self.insert(&def.name, oid);
                        added += 1;
                        progressed = true;
                    }
                    None => still.push(def),
                }
            }
            pending = still;
            if !progressed || pending.is_empty() {
                break;
            }
        }
        added
    }

    fn resolve_tokens(&self, tokens: &[Token]) -> Option<Vec<u32>> {
        let mut oid: Vec<u32> = Vec::new();
        for (i, tok) in tokens.iter().enumerate() {
            match tok {
                Token::Num(n) => oid.push(*n),
                Token::NamedNum(_, n) => oid.push(*n),
                Token::Named(name) => {
                    let resolved = self.by_name.get(name)?;
                    if i == 0 {
                        oid = resolved.clone();
                    } else {
                        oid.extend_from_slice(resolved);
                    }
                }
            }
        }
        if oid.is_empty() { None } else { Some(oid) }
    }
}

fn dotted(oid: &[u32]) -> String {
    oid.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Named(String),
    Num(u32),
    NamedNum(String, u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawDef {
    name: String,
    tokens: Vec<Token>,
}

/// Extract `<name> ... ::= { <oid body> }` assignments from MIB text. This is a
/// name-extractor, not a full SMI parser: it ignores types, constraints, and
/// textual conventions, which are not needed to translate walk output.
fn parse_mib(text: &str) -> Vec<RawDef> {
    // name, one of the SMI macros, then (non-greedily) up to the first "::= { body }".
    let re = Regex::new(
        r"(?s)([A-Za-z][\w-]*)\s+(?:OBJECT\s+IDENTIFIER|OBJECT-TYPE|MODULE-IDENTITY|OBJECT-IDENTITY|NOTIFICATION-TYPE|OBJECT-GROUP|NOTIFICATION-GROUP|MODULE-COMPLIANCE|AGENT-CAPABILITIES).*?::=\s*\{([^}]*)\}",
    )
    .unwrap();

    let tok_re = Regex::new(r"^([A-Za-z][\w-]*)\((\d+)\)$").unwrap();
    let mut defs = Vec::new();
    for cap in re.captures_iter(text) {
        let name = cap[1].to_string();
        let body = &cap[2];
        let mut tokens = Vec::new();
        for raw in body.split_whitespace() {
            if let Ok(n) = raw.parse::<u32>() {
                tokens.push(Token::Num(n));
            } else if let Some(m) = tok_re.captures(raw) {
                tokens.push(Token::NamedNum(m[1].to_string(), m[2].parse().unwrap()));
            } else {
                tokens.push(Token::Named(raw.to_string()));
            }
        }
        if !tokens.is_empty() {
            defs.push(RawDef { name, tokens });
        }
    }
    defs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_builtins() {
        let mib = Mib::with_builtins();
        assert_eq!(mib.translate(&[1, 3, 6, 1, 2, 1, 1, 1, 0]), "sysDescr.0");
        assert_eq!(
            mib.translate(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 3]),
            "ifDescr.3"
        );
        assert_eq!(mib.translate(&[1, 3, 6, 1, 2, 1, 1]), "system");
        // Unknown subtree falls back to numeric.
        assert_eq!(
            mib.translate(&[1, 3, 6, 1, 4, 1, 9999, 1]),
            "enterprises.9999.1"
        );
    }

    #[test]
    fn resolve_input_forms() {
        let mib = Mib::with_builtins();
        assert_eq!(
            mib.resolve("1.3.6.1.2.1.1"),
            Some(vec![1, 3, 6, 1, 2, 1, 1])
        );
        assert_eq!(mib.resolve(".1.3.6.1"), Some(vec![1, 3, 6, 1]));
        assert_eq!(mib.resolve("system"), Some(vec![1, 3, 6, 1, 2, 1, 1]));
        assert_eq!(
            mib.resolve("sysDescr.0"),
            Some(vec![1, 3, 6, 1, 2, 1, 1, 1, 0])
        );
        assert_eq!(mib.resolve("nosuchname"), None);
    }

    #[test]
    fn loads_simple_mib() {
        // A compact MIB snippet using several assignment styles.
        let text = r#"
            ACME-MIB DEFINITIONS ::= BEGIN
            acme OBJECT IDENTIFIER ::= { enterprises 99999 }
            products OBJECT IDENTIFIER ::= { acme 1 }
            widgetName OBJECT-TYPE
                SYNTAX DisplayString
                MAX-ACCESS read-only
                STATUS current
                DESCRIPTION "the widget name"
                ::= { products 2 }
            END
        "#;
        let mut mib = Mib::with_builtins();
        let added = mib.load_mib(text);
        assert_eq!(added, 3);
        assert_eq!(mib.resolve("acme"), Some(vec![1, 3, 6, 1, 4, 1, 99999]));
        assert_eq!(
            mib.translate(&[1, 3, 6, 1, 4, 1, 99999, 1, 2, 0]),
            "widgetName.0"
        );
    }

    #[test]
    fn loads_mib_with_named_number_chain() {
        let text = r#"
            myroot OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 4 1 12345 }
        "#;
        let mut mib = Mib::with_builtins();
        assert_eq!(mib.load_mib(text), 1);
        assert_eq!(mib.resolve("myroot"), Some(vec![1, 3, 6, 1, 4, 1, 12345]));
    }

    #[test]
    fn out_of_order_definitions_resolve() {
        // child defined before its parent.
        let text = r#"
            child OBJECT IDENTIFIER ::= { parentnode 1 }
            parentnode OBJECT IDENTIFIER ::= { enterprises 42 }
        "#;
        let mut mib = Mib::with_builtins();
        assert_eq!(mib.load_mib(text), 2);
        assert_eq!(mib.resolve("child"), Some(vec![1, 3, 6, 1, 4, 1, 42, 1]));
    }

    #[test]
    fn unresolvable_parent_is_skipped() {
        let text = "orphan OBJECT IDENTIFIER ::= { unknownparent 1 }";
        let mut mib = Mib::with_builtins();
        assert_eq!(mib.load_mib(text), 0);
    }
}

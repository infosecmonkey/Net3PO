//! RDAP (RFC 9083) registration lookup for an IP address: the registered
//! network, its owner and the abuse contact. Pure helpers here; the HTTPS
//! request is made in `commands`. RDAP answers are untrusted input: entity
//! nesting, list lengths and string sizes are all bounded.

use std::net::IpAddr;

use serde::Serialize;
use serde_json::Value;

/// Deepest entity nesting walked (ARIN nests abuse under the registrant).
const MAX_ENTITY_DEPTH: usize = 4;
/// Most entities inspected in one answer.
const MAX_ENTITIES: usize = 60;
/// Longest string kept from any field.
const MAX_STR: usize = 300;
/// Most values kept in any list (emails, phones, CIDRs, contacts).
const MAX_LIST: usize = 8;

/// RDAP base URL for a regional internet registry, by the short name Team
/// Cymru reports. Unknown or empty registries start at ARIN, which
/// redirects to the registry that holds the address.
pub fn base_url(registry: &str) -> &'static str {
    match registry.trim().to_ascii_lowercase().as_str() {
        "ripencc" | "ripe" => "https://rdap.db.ripe.net/ip/",
        "apnic" => "https://rdap.apnic.net/ip/",
        "lacnic" => "https://rdap.lacnic.net/rdap/ip/",
        "afrinic" => "https://rdap.afrinic.net/rdap/ip/",
        _ => "https://rdap.arin.net/registry/ip/",
    }
}

/// Full query URL for an address.
pub fn query_url(registry: &str, ip: IpAddr) -> String {
    format!("{}{ip}", base_url(registry))
}

/// A contact from an RDAP entity's vCard.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RdapContact {
    pub handle: String,
    pub name: String,
    pub roles: Vec<String>,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
}

/// The parts of an RDAP IP network answer worth showing.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RdapNetwork {
    pub handle: String,
    pub name: String,
    /// `start - end` as registered.
    pub range: String,
    pub cidrs: Vec<String>,
    pub country: String,
    /// Allocation type, for example "DIRECT ALLOCATION" or "ASSIGNED PA".
    pub net_type: String,
    /// Registrant organisation name, when one is listed.
    pub owner: String,
    /// Contacts with the abuse role.
    pub abuse: Vec<RdapContact>,
    pub registered: String,
    pub last_changed: String,
}

fn clip(s: &str) -> String {
    let s = s.trim();
    match s.char_indices().nth(MAX_STR) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s.to_string(),
    }
}

fn str_at(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .map(clip)
        .unwrap_or_default()
}

fn push_unique(list: &mut Vec<String>, s: String) {
    if !s.is_empty() && list.len() < MAX_LIST && !list.contains(&s) {
        list.push(s);
    }
}

/// Read `fn`, `org`, `email` and `tel` out of a jCard (RFC 7095) array:
/// `["vcard", [["fn", {}, "text", "Name"], ...]]`.
fn read_vcard(v: &Value, c: &mut RdapContact) {
    let Some(props) = v.get(1).and_then(Value::as_array) else {
        return;
    };
    let mut org = String::new();
    for p in props.iter().take(100) {
        let Some(p) = p.as_array() else { continue };
        let (Some(name), Some(val)) = (p.first().and_then(Value::as_str), p.get(3)) else {
            continue;
        };
        let text = val.as_str().map(clip).unwrap_or_default();
        match name {
            "fn" if c.name.is_empty() => c.name = text,
            "org" if org.is_empty() => org = text,
            "email" => push_unique(&mut c.emails, text),
            "tel" => push_unique(&mut c.phones, clip(text.trim_start_matches("tel:"))),
            _ => {}
        }
    }
    if c.name.is_empty() {
        c.name = org;
    }
}

fn read_entity(e: &Value) -> RdapContact {
    let mut c = RdapContact {
        handle: str_at(e, "handle"),
        ..Default::default()
    };
    if let Some(roles) = e.get("roles").and_then(Value::as_array) {
        for r in roles.iter().filter_map(Value::as_str) {
            push_unique(&mut c.roles, clip(r));
        }
    }
    if let Some(card) = e.get("vcardArray") {
        read_vcard(card, &mut c);
    }
    c
}

/// Depth-first walk of `entities`, bounded in depth and count.
fn collect_entities(v: &Value, depth: usize, out: &mut Vec<RdapContact>) {
    if depth >= MAX_ENTITY_DEPTH {
        return;
    }
    let Some(list) = v.get("entities").and_then(Value::as_array) else {
        return;
    };
    for e in list {
        if out.len() >= MAX_ENTITIES {
            return;
        }
        out.push(read_entity(e));
        collect_entities(e, depth + 1, out);
    }
}

fn event_date(v: &Value, action: &str) -> String {
    v.get("events")
        .and_then(Value::as_array)
        .and_then(|evs| {
            evs.iter()
                .find(|e| e.get("eventAction").and_then(Value::as_str) == Some(action))
        })
        .map(|e| str_at(e, "eventDate"))
        .unwrap_or_default()
}

/// Parse an RDAP `ip network` object. Returns an error when the JSON is
/// not an IP network answer (for example an RDAP error object).
pub fn parse_network(v: &Value) -> Result<RdapNetwork, String> {
    if v.get("objectClassName").and_then(Value::as_str) != Some("ip network") {
        let why = v
            .get("title")
            .or_else(|| v.get("description").and_then(|d| d.get(0)))
            .and_then(Value::as_str)
            .map(clip)
            .unwrap_or_else(|| "not an IP network record".into());
        return Err(why);
    }
    let start = str_at(v, "startAddress");
    let end = str_at(v, "endAddress");
    let mut cidrs = Vec::new();
    if let Some(list) = v.get("cidr0_cidrs").and_then(Value::as_array) {
        for c in list {
            let prefix = c
                .get("v4prefix")
                .or_else(|| c.get("v6prefix"))
                .and_then(Value::as_str);
            if let (Some(p), Some(len)) = (prefix, c.get("length").and_then(Value::as_u64)) {
                push_unique(&mut cidrs, clip(&format!("{p}/{len}")));
            }
        }
    }

    let mut contacts = Vec::new();
    collect_entities(v, 0, &mut contacts);
    let owner = contacts
        .iter()
        .find(|c| c.roles.iter().any(|r| r == "registrant") && !c.name.is_empty())
        .map(|c| c.name.clone())
        .unwrap_or_default();
    let mut abuse: Vec<RdapContact> = Vec::new();
    for c in contacts
        .into_iter()
        .filter(|c| c.roles.iter().any(|r| r == "abuse"))
    {
        if abuse.len() < MAX_LIST
            && !abuse
                .iter()
                .any(|a| a.handle == c.handle && a.emails == c.emails)
        {
            abuse.push(c);
        }
    }

    Ok(RdapNetwork {
        handle: str_at(v, "handle"),
        name: str_at(v, "name"),
        range: if start.is_empty() {
            String::new()
        } else {
            format!("{start} - {end}")
        },
        cidrs,
        country: str_at(v, "country"),
        net_type: str_at(v, "type"),
        owner,
        abuse,
        registered: event_date(v, "registration"),
        last_changed: event_date(v, "last changed"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn card(name: &str, email: &str) -> Value {
        json!(["vcard", [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", name],
            ["email", {}, "text", email],
            ["tel", {"type": ["work", "voice"]}, "uri", "tel:+1-555-0100"]
        ]])
    }

    #[test]
    fn urls() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(
            query_url("arin", ip),
            "https://rdap.arin.net/registry/ip/192.0.2.10"
        );
        assert_eq!(
            query_url("RIPENCC", ip),
            "https://rdap.db.ripe.net/ip/192.0.2.10"
        );
        assert_eq!(
            query_url("", ip),
            "https://rdap.arin.net/registry/ip/192.0.2.10"
        );
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            query_url("apnic", v6),
            "https://rdap.apnic.net/ip/2001:db8::1"
        );
    }

    #[test]
    fn parses_arin_shape() {
        // ARIN style: abuse nested under the registrant entity.
        let v = json!({
            "objectClassName": "ip network",
            "handle": "NET-192-0-2-0-1",
            "name": "EXAMPLE-NET",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "type": "DIRECT ALLOCATION",
            "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
            "events": [
                {"eventAction": "registration", "eventDate": "2001-02-03T00:00:00-05:00"},
                {"eventAction": "last changed", "eventDate": "2024-05-06T00:00:00-04:00"}
            ],
            "entities": [{
                "handle": "EXORG",
                "roles": ["registrant"],
                "vcardArray": card("Example Org", "info@example.net"),
                "entities": [
                    {"handle": "ABUSE1-ARIN", "roles": ["abuse"], "vcardArray": card("Abuse Desk", "abuse@example.net")},
                    {"handle": "TECH1-ARIN", "roles": ["technical"], "vcardArray": card("NOC", "noc@example.net")}
                ]
            }]
        });
        let n = parse_network(&v).unwrap();
        assert_eq!(n.name, "EXAMPLE-NET");
        assert_eq!(n.range, "192.0.2.0 - 192.0.2.255");
        assert_eq!(n.cidrs, vec!["192.0.2.0/24"]);
        assert_eq!(n.owner, "Example Org");
        assert_eq!(n.abuse.len(), 1);
        assert_eq!(n.abuse[0].emails, vec!["abuse@example.net"]);
        assert_eq!(n.abuse[0].phones, vec!["+1-555-0100"]);
        assert_eq!(n.registered, "2001-02-03T00:00:00-05:00");
        assert_eq!(n.last_changed, "2024-05-06T00:00:00-04:00");
    }

    #[test]
    fn parses_ripe_shape_with_org_property() {
        // RIPE style: top-level abuse role, owner name in "org" with an empty fn.
        let v = json!({
            "objectClassName": "ip network",
            "handle": "198.51.100.0 - 198.51.100.255",
            "name": "EXAMPLE-RIPE",
            "country": "NL",
            "entities": [
                {"handle": "ORG-EX1-RIPE", "roles": ["registrant"],
                 "vcardArray": ["vcard", [["fn", {}, "text", ""], ["org", {}, "text", "Example BV"]]]},
                {"handle": "AR1-RIPE", "roles": ["abuse"], "vcardArray": card("Abuse", "abuse@example.nl")}
            ]
        });
        let n = parse_network(&v).unwrap();
        assert_eq!(n.country, "NL");
        assert_eq!(n.owner, "Example BV");
        assert_eq!(n.abuse[0].emails, vec!["abuse@example.nl"]);
        assert_eq!(n.range, "");
    }

    #[test]
    fn hostile_and_error_answers() {
        let err = json!({"errorCode": 404, "title": "Not Found"});
        assert_eq!(parse_network(&err).unwrap_err(), "Not Found");
        assert!(parse_network(&json!([1, 2])).is_err());

        // Deep nesting stops at the limit instead of recursing forever.
        let mut deep = json!({"handle": "leaf", "roles": ["abuse"]});
        for i in 0..50 {
            deep = json!({"handle": format!("n{i}"), "roles": ["x"], "entities": [deep]});
        }
        let v = json!({"objectClassName": "ip network", "entities": [deep]});
        let n = parse_network(&v).unwrap();
        assert!(n.abuse.is_empty());

        // Many contacts and a huge name are bounded.
        let many: Vec<Value> = (0..500)
            .map(|i| json!({"handle": format!("A{i}"), "roles": ["abuse"], "vcardArray": card(&"x".repeat(5000), "a@b.c")}))
            .collect();
        let v = json!({"objectClassName": "ip network", "entities": many});
        let n = parse_network(&v).unwrap();
        assert_eq!(n.abuse.len(), MAX_LIST);
        assert!(n.abuse[0].name.chars().count() <= MAX_STR + 3);
    }
}

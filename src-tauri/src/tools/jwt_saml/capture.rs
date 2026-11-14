//! Find SAML messages inside whatever an engineer captured: a SAML-tracer
//! JSON export, a browser HAR file, an HTML login form, a URL, FortiGate
//! `diagnose debug application samld` output, or a bare Base64 blob. Each
//! candidate is decoded to XML, and duplicates (the same message seen twice)
//! are dropped.

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

/// Largest capture scanned (HAR files can be big).
pub const MAX_CAPTURE: usize = 32 * 1024 * 1024;
/// Most messages listed.
const MAX_FOUND: usize = 50;

fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid built-in pattern")
}

static XML_START: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"<((?:[A-Za-z][\w.-]*:)?(?:Response|AuthnRequest|LogoutRequest|LogoutResponse|ArtifactResponse|Assertion))[\s>/]",
    )
});
static PARAM: LazyLock<Regex> = LazyLock::new(|| re(r#"SAML(Response|Request)=([^&\s"'<>]+)"#));
static HAR_PARAM: LazyLock<Regex> =
    LazyLock::new(|| re(r#""name"\s*:\s*"SAML(Response|Request)"\s*,\s*"value"\s*:\s*"([^"]+)""#));
static HTML_INPUT: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"(?i)name\s*=\s*\\?["']SAML(Response|Request)\\?["'][^>]*?value\s*=\s*\\?["']([^"'\\]+)"#)
});
/// Base64 of "<?xml ", "<samlp", "<saml2", "<saml:" and "<saml2p:".
static B64_BLOB: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?:PD94bWwg|PHNhbWxw|PHNhbWwy|PHNhbWw6)[A-Za-z0-9+/=]{60,}"));
static ROOT: LazyLock<Regex> = LazyLock::new(|| re(r"<(?:[A-Za-z][\w.-]*:)?(\w+)[\s>]"));

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Found {
    /// "Response", "AuthnRequest", ...
    pub message: String,
    /// Where it came from: "XML in the text", "SAMLResponse parameter", ...
    pub source: String,
    pub line: usize,
    /// Ready to hand to `saml::inspect` (XML, Base64 or a parameter value).
    #[serde(skip)]
    pub data: String,
}

fn line_of(text: &str, pos: usize) -> usize {
    text[..pos.min(text.len())].matches('\n').count() + 1
}

/// Undo JSON string escaping (SAML-tracer stores decoded XML in JSON).
fn json_unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let h: String = it.by_ref().take(4).collect();
                if let Some(ch) = u32::from_str_radix(&h, 16).ok().and_then(char::from_u32) {
                    out.push(ch);
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// The root element name of an XML message.
fn root(xml: &str) -> String {
    let body = xml.trim_start();
    let body = body
        .strip_prefix("<?xml")
        .and_then(|r| r.find("?>").map(|i| &r[i + 2..]))
        .unwrap_or(body);
    ROOT.captures(body)
        .map(|c| c[1].to_string())
        .unwrap_or_else(|| "XML".into())
}

/// Every SAML message found in `text`, in order of appearance.
pub fn find(text: &str) -> Vec<Found> {
    let mut out: Vec<(usize, Found, String)> = Vec::new();
    let mut taken: Vec<(usize, usize)> = Vec::new();

    // Whole XML messages (raw, or JSON-escaped in a SAML-tracer export).
    let mut from = 0;
    while let Some(m) = XML_START.captures_at(text, from) {
        let start = m.get(0).map(|x| x.start()).unwrap_or(0);
        let qname = &m[1];
        let close = format!("</{qname}>");
        from = start + 1;
        if taken.iter().any(|&(a, b)| start >= a && start < b) {
            continue;
        }
        let Some(rel) = text[start..].find(&close) else {
            continue;
        };
        let end = start + rel + close.len();
        let raw = &text[start..end];
        let xml = json_unescape(raw);
        let msg = root(&xml);
        // An Assertion inside a Response is reported with its Response.
        taken.push((start, end));
        let source = if raw.contains("\\\"") {
            "XML in a JSON export (SAML-tracer)"
        } else {
            "XML in the text"
        };
        out.push((
            start,
            Found {
                message: msg,
                source: source.into(),
                line: line_of(text, start),
                data: xml.clone(),
            },
            xml,
        ));
        from = end;
        if out.len() >= MAX_FOUND {
            break;
        }
    }

    // Parameters: URLs, form bodies, HAR fields, HTML hidden inputs.
    for (r, source) in [
        (&*HAR_PARAM, "HAR form field"),
        (&*HTML_INPUT, "HTML form field"),
        (&*PARAM, "parameter"),
    ] {
        for c in r.captures_iter(text) {
            if out.len() >= MAX_FOUND {
                break;
            }
            let pos = c.get(0).map(|x| x.start()).unwrap_or(0);
            if taken.iter().any(|&(a, b)| pos >= a && pos < b) {
                continue;
            }
            let value = c[2]
                .replace("\\/", "/")
                .replace("\\u003d", "=")
                .replace("\\u0026", "&");
            let kind = format!("SAML{}", &c[1]);
            if let Ok((xml, _)) = super::saml::to_xml(&value) {
                taken.push((pos, c.get(0).map(|x| x.end()).unwrap_or(pos)));
                out.push((
                    pos,
                    Found {
                        message: root(&xml),
                        source: format!("{kind} {source}"),
                        line: line_of(text, pos),
                        data: value,
                    },
                    xml,
                ));
            }
        }
    }

    // Bare Base64 blobs that decode to SAML XML.
    for m in B64_BLOB.find_iter(text) {
        if out.len() >= MAX_FOUND {
            break;
        }
        if taken.iter().any(|&(a, b)| m.start() >= a && m.start() < b) {
            continue;
        }
        if let Ok((xml, _)) = super::saml::to_xml(m.as_str()) {
            out.push((
                m.start(),
                Found {
                    message: root(&xml),
                    source: "Base64 in the text".into(),
                    line: line_of(text, m.start()),
                    data: m.as_str().to_string(),
                },
                xml,
            ));
        }
    }

    out.sort_by_key(|(pos, _, _)| *pos);
    // Drop repeats of the same message (HAR files often hold it twice).
    let mut seen: Vec<String> = Vec::new();
    let mut result = Vec::new();
    for (_, f, xml) in out {
        let key: String = xml.split_whitespace().collect();
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        result.push(f);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const RESP: &str = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Destination="https://fgt.example.com/remote/saml/login"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a1"><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn fortigate_samld_style_text() {
        let text = format!(
            "__samld_sp_login_resp [802]: Clean\nsamld_sp_login_resp [1083]:\n**** SAML Response:\n{RESP}\nsamld_send_common_reply [99]: Code: 0\n"
        );
        let f = find(&text);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].message, "Response");
        assert_eq!(f[0].line, 4);
        assert!(f[0].data.starts_with("<samlp:Response"));
    }

    #[test]
    fn har_and_saml_tracer() {
        let enc = b64(RESP)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        let har = format!(
            r#"{{"log":{{"entries":[{{"request":{{"method":"POST","postData":{{"text":"SAMLResponse={enc}&RelayState=x","params":[{{"name":"SAMLResponse","value":"{}"}}]}}}}}}]}}}}"#,
            b64(RESP).replace('/', "\\/")
        );
        let f = find(&har);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].message, "Response");
        let tracer = format!(
            r#"{{"requests":[{{"url":"https://fgt.example.com/remote/saml/login","saml":"{}"}}]}}"#,
            RESP.replace('"', "\\\"")
        );
        let f = find(&tracer);
        assert_eq!(f.len(), 1);
        assert!(f[0].source.contains("SAML-tracer"));
        assert!(super::super::saml::inspect(&f[0].data, &Default::default(), 0).is_ok());
    }

    #[test]
    fn several_messages_in_order() {
        use std::io::Write;
        let req =
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_q1"/>"#;
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(req.as_bytes()).unwrap();
        let deflated = base64::engine::general_purpose::STANDARD.encode(enc.finish().unwrap());
        let url = format!(
            "GET https://idp.example.com/sso?SAMLRequest={}&RelayState=abc",
            deflated
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        );
        let form = format!(
            r#"<form method="post"><input type="hidden" name="SAMLResponse" value="{}"/></form>"#,
            b64(RESP)
        );
        let f = find(&format!("{url}\n...\n{form}\n"));
        assert_eq!(
            f.iter().map(|x| x.message.as_str()).collect::<Vec<_>>(),
            vec!["AuthnRequest", "Response"]
        );
        assert_eq!(f[1].line, 3);
    }

    #[test]
    fn bare_base64_and_nothing() {
        let f = find(&format!("pasted:\n{}\n", b64(RESP)));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].source, "Base64 in the text");
        assert!(find("no saml here at all").is_empty());
        assert!(find("<samlp:Response unterminated").is_empty());
    }
}

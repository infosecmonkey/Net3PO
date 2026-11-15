//! SAML inspection: decode a SAMLResponse or request (POST binding Base64,
//! Redirect binding Base64 + DEFLATE, URL-encoded or raw XML) and read the
//! fields that matter for troubleshooting SSO. Times, audience, recipient
//! and issuer are compared with the user's expectations. XML signatures are
//! located and described but not verified: that needs XML canonicalization
//! this tool does not implement, and the result says so. External entities
//! are never resolved.

use std::io::Read;

use base64::Engine as _;
use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};

use super::jwt::Check;

const MAX_INPUT: usize = 1024 * 1024;
const MAX_XML: u64 = 4 * 1024 * 1024;
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Expect {
    pub issuer: String,
    pub audience: String,
    /// Expected Destination / Recipient (the SP's ACS URL).
    pub recipient: String,
    pub skew_secs: i64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
    /// The element the signature sits in: Response, Assertion, ...
    pub on: String,
    pub method: String,
    pub digest: String,
    pub weak: bool,
    pub cert_subject: String,
    pub cert_not_after_ms: Option<i64>,
    pub cert_sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SamlResult {
    pub binding: String,
    pub xml: String,
    pub message: String,
    pub id: String,
    pub issue_instant: String,
    pub destination: String,
    pub in_response_to: String,
    pub issuer: String,
    pub status: String,
    pub assertion_issuer: String,
    pub name_id: String,
    pub name_id_format: String,
    pub recipient: String,
    pub not_before: String,
    pub not_on_or_after: String,
    pub confirmation_not_on_or_after: String,
    pub audiences: Vec<String>,
    pub authn_instant: String,
    pub session_index: String,
    pub attributes: Vec<(String, Vec<String>)>,
    pub signatures: Vec<SignatureInfo>,
    pub encrypted_assertion: bool,
    pub checks: Vec<Check>,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = (b[i] == b'%')
            .then(|| b.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (b[i], hex) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Turn whatever was pasted into XML, saying which binding it looked like.
pub(crate) fn to_xml(input: &str) -> Result<(String, String), String> {
    let mut s = input.trim().to_string();
    if s.starts_with('<') {
        return Ok((s, "raw XML".into()));
    }
    // A query string or form body: take the SAMLResponse/SAMLRequest value.
    if let Some(v) = s.split(['&', '?']).find_map(|kv| {
        kv.strip_prefix("SAMLResponse=")
            .or_else(|| kv.strip_prefix("SAMLRequest="))
    }) {
        s = v.to_string();
    }
    let was_urlencoded = s.contains('%');
    if was_urlencoded {
        s = pct_decode(&s);
    }
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(clean.trim_end_matches('='))
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(clean.trim_end_matches('='))
        })
        .map_err(|_| "not SAML XML, Base64 or a SAMLResponse/SAMLRequest parameter".to_string())?;
    if bytes.first() == Some(&b'<') {
        return Ok((
            String::from_utf8_lossy(&bytes).into_owned(),
            if was_urlencoded {
                "POST binding (Base64, URL-encoded)".into()
            } else {
                "POST binding (Base64)".into()
            },
        ));
    }
    // Redirect binding: raw DEFLATE.
    let mut out = String::new();
    flate2::read::DeflateDecoder::new(&bytes[..])
        .take(MAX_XML)
        .read_to_string(&mut out)
        .map_err(|_| "decoded data is neither XML nor DEFLATE-compressed XML".to_string())?;
    if !out.trim_start().starts_with('<') {
        return Err("decompressed data is not XML".into());
    }
    Ok((out, "Redirect binding (Base64 + DEFLATE)".into()))
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_string()
}

fn attr(e: &quick_xml::events::BytesStart, key: &str) -> String {
    e.attributes()
        .flatten()
        .find(|a| local(a.key.as_ref()) == key)
        .and_then(|a| {
            a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .ok()
                .map(|v| v.into_owned())
        })
        .unwrap_or_default()
}

fn ts(s: &str) -> Option<i64> {
    s.trim()
        .parse::<jiff::Timestamp>()
        .ok()
        .map(|t| t.as_second())
}

fn check(name: &str, status: &str, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status: status.into(),
        detail: detail.into(),
    }
}

pub fn inspect(input: &str, exp: &Expect, now: i64) -> Result<SamlResult, String> {
    if input.len() > MAX_INPUT {
        return Err("input larger than 1 MB".into());
    }
    let (xml, binding) = to_xml(input)?;
    if xml.len() as u64 > MAX_XML {
        return Err("decoded XML larger than 4 MB".into());
    }
    let mut r = SamlResult {
        binding,
        ..Default::default()
    };
    let mut reader = Reader::from_str(&xml);
    // Trim whole values at the end tag, not each fragment around an entity.
    reader.config_mut().trim_text(false);
    let mut stack: Vec<String> = Vec::new();
    let mut cur_attr: Option<(String, Vec<String>)> = None;
    let mut sig: Option<SignatureInfo> = None;
    let mut text = String::new();
    loop {
        let ev = reader
            .read_event()
            .map_err(|e| format!("XML error at byte {}: {e}", reader.error_position()))?;
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let empty = matches!(ev, Event::Empty(_));
                let name = local(e.name().as_ref());
                if stack.len() >= MAX_DEPTH {
                    return Err("XML nested too deeply".into());
                }
                let parent = stack.last().cloned().unwrap_or_default();
                match name.as_str() {
                    n if stack.is_empty() => {
                        r.message = n.to_string();
                        r.id = attr(e, "ID");
                        r.issue_instant = attr(e, "IssueInstant");
                        r.destination = attr(e, "Destination");
                        r.in_response_to = attr(e, "InResponseTo");
                    }
                    "StatusCode" if r.status.is_empty() => {
                        r.status = attr(e, "Value")
                            .rsplit(':')
                            .next()
                            .unwrap_or("")
                            .to_string()
                    }
                    "StatusCode" => {
                        r.status = format!(
                            "{} / {}",
                            r.status,
                            attr(e, "Value").rsplit(':').next().unwrap_or("")
                        )
                    }
                    "SubjectConfirmationData" => {
                        r.recipient = attr(e, "Recipient");
                        r.confirmation_not_on_or_after = attr(e, "NotOnOrAfter");
                    }
                    "Conditions" => {
                        r.not_before = attr(e, "NotBefore");
                        r.not_on_or_after = attr(e, "NotOnOrAfter");
                    }
                    "AuthnStatement" => {
                        r.authn_instant = attr(e, "AuthnInstant");
                        r.session_index = attr(e, "SessionIndex");
                    }
                    "NameID" => r.name_id_format = attr(e, "Format"),
                    "Attribute" => {
                        let n = attr(e, "FriendlyName");
                        let n = if n.is_empty() {
                            attr(e, "Name")
                        } else {
                            format!("{n} ({})", attr(e, "Name"))
                        };
                        cur_attr = Some((n, Vec::new()));
                    }
                    "EncryptedAssertion" => r.encrypted_assertion = true,
                    "Signature" => {
                        sig = Some(SignatureInfo {
                            on: parent.clone(),
                            ..Default::default()
                        })
                    }
                    "SignatureMethod" => {
                        if let Some(s) = sig.as_mut() {
                            s.method = attr(e, "Algorithm");
                        }
                    }
                    "DigestMethod" => {
                        if let Some(s) = sig.as_mut() {
                            s.digest = attr(e, "Algorithm");
                        }
                    }
                    _ => {}
                }
                if !empty {
                    stack.push(name);
                }
                text.clear();
            }
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::GeneralRef(g) => {
                if let Ok(Some(c)) = g.resolve_char_ref() {
                    text.push(c);
                } else {
                    let ent = g.xml10_content();
                    text.push_str(match ent.as_ref() {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => "",
                    });
                }
            }
            Event::End(_) => {
                let name = stack.pop().unwrap_or_default();
                let parent = stack.last().cloned().unwrap_or_default();
                let value = text.trim().to_string();
                match name.as_str() {
                    "Issuer" if parent == "Assertion" => r.assertion_issuer = value.clone(),
                    "Issuer" if r.issuer.is_empty() => r.issuer = value.clone(),
                    "NameID" => r.name_id = value.clone(),
                    "Audience" if r.audiences.len() < 50 => r.audiences.push(value.clone()),
                    "AttributeValue" => {
                        if let Some((_, vals)) = cur_attr.as_mut()
                            && vals.len() < 50
                        {
                            vals.push(value.chars().take(500).collect());
                        }
                    }
                    "Attribute" => {
                        if let Some(a) = cur_attr.take()
                            && r.attributes.len() < 200
                        {
                            r.attributes.push(a);
                        }
                    }
                    "X509Certificate" => {
                        if let Some(s) = sig.as_mut() {
                            let der = base64::engine::general_purpose::STANDARD
                                .decode(
                                    value
                                        .chars()
                                        .filter(|c| !c.is_whitespace())
                                        .collect::<String>(),
                                )
                                .unwrap_or_default();
                            if let Ok(c) =
                                crate::tools::tls_inspector::cert::decode_cert(&der, now * 1000)
                            {
                                s.cert_subject = c.subject;
                                s.cert_not_after_ms = Some(c.not_after_ms);
                                s.cert_sha256 = c.sha256;
                            }
                        }
                    }
                    "Signature" => {
                        if let Some(mut s) = sig.take() {
                            s.weak = s.method.contains("sha1") || s.digest.contains("sha1");
                            if r.signatures.len() < 10 {
                                r.signatures.push(s);
                            }
                        }
                    }
                    _ => {}
                }
                text.clear();
            }
            Event::Eof => break,
            _ => {} // DocType (never expanded), comments, PIs
        }
    }
    if r.message.is_empty() {
        return Err("no XML element found".into());
    }
    r.xml = xml.chars().take(200_000).collect();

    // Checks against expectations and the clock.
    let skew = exp.skew_secs.clamp(0, 3600);
    let mut checks = Vec::new();
    if !r.status.is_empty() {
        checks.push(check(
            "Status",
            if r.status.starts_with("Success") {
                "pass"
            } else {
                "fail"
            },
            r.status.clone(),
        ));
    }
    if let Some(nb) = ts(&r.not_before) {
        checks.push(if now + skew < nb {
            check(
                "Conditions NotBefore",
                "fail",
                format!("not valid until {}", r.not_before),
            )
        } else {
            check("Conditions NotBefore", "pass", r.not_before.clone())
        });
    }
    for (label, v) in [
        ("Conditions NotOnOrAfter", &r.not_on_or_after),
        (
            "SubjectConfirmation NotOnOrAfter",
            &r.confirmation_not_on_or_after,
        ),
    ] {
        if let Some(t) = ts(v) {
            checks.push(if now - skew >= t {
                check(label, "fail", format!("expired at {v}"))
            } else {
                check(label, "pass", format!("valid until {v}"))
            });
        }
    }
    if !exp.audience.trim().is_empty() {
        let ok = r.audiences.iter().any(|a| a == exp.audience.trim());
        checks.push(check(
            "Audience",
            if ok { "pass" } else { "fail" },
            if ok {
                format!("includes {}", exp.audience.trim())
            } else {
                format!(
                    "audiences {:?} do not include \"{}\"",
                    r.audiences,
                    exp.audience.trim()
                )
            },
        ));
    }
    if !exp.recipient.trim().is_empty() {
        let want = exp.recipient.trim();
        for (label, v) in [("Destination", &r.destination), ("Recipient", &r.recipient)] {
            if !v.is_empty() {
                checks.push(check(
                    label,
                    if v == want { "pass" } else { "fail" },
                    if v == want {
                        format!("matches {want}")
                    } else {
                        format!("\"{v}\", expected \"{want}\"")
                    },
                ));
            }
        }
    }
    if !exp.issuer.trim().is_empty() {
        let got = if r.assertion_issuer.is_empty() {
            &r.issuer
        } else {
            &r.assertion_issuer
        };
        checks.push(check(
            "Issuer",
            if got == exp.issuer.trim() {
                "pass"
            } else {
                "fail"
            },
            format!("\"{got}\""),
        ));
    }
    if r.signatures.is_empty() && !r.encrypted_assertion {
        let is_response = r.message == "Response" || r.message == "Assertion";
        let redirect = r.binding.starts_with("Redirect");
        // Redirect binding signs the URL (Signature and SigAlg parameters),
        // never the XML, and requests are often unsigned by design.
        let url_signed = input
            .split(['&', '?'])
            .any(|kv| kv.starts_with("Signature="));
        if is_response {
            checks.push(check("Signature", "fail", "no XML signature present; a service provider should reject an unsigned response or assertion"));
        } else if redirect && url_signed {
            checks.push(check("Signature", "info", "signed in the URL (Redirect binding Signature and SigAlg parameters); that signature is not verified here"));
        } else if redirect {
            checks.push(check("Signature", "info", "no XML signature, as expected for the Redirect binding, which signs the URL; this paste has no Signature parameter, so the request is unsigned or the parameter was not included"));
        } else {
            checks.push(check("Signature", "info", format!("{} is not signed; signing requests is optional unless the other party requires it", if r.message.is_empty() { "the message" } else { &r.message })));
        }
    }
    for s in &r.signatures {
        if s.weak {
            checks.push(check(
                "Signature algorithm",
                "fail",
                format!("{} signature uses SHA-1 ({})", s.on, s.method),
            ));
        }
        if let Some(na) = s.cert_not_after_ms
            && na / 1000 < now
        {
            checks.push(check("Signing certificate", "info", "the embedded signing certificate is expired (many SPs ignore certificate dates, but check)"));
        }
    }
    if r.encrypted_assertion {
        checks.push(check(
            "Assertion",
            "info",
            "the assertion is encrypted; its contents need the SP's private key",
        ));
    }
    r.checks = checks;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const XML: &str = r#"<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" IssueInstant="2026-11-14T12:00:00Z" Destination="https://sp.example.com/acs" InResponseTo="_req9">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" IssueInstant="2026-11-14T12:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></ds:Reference></ds:SignedInfo></ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com &xxe;</saml:NameID>
      <saml:SubjectConfirmation><saml:SubjectConfirmationData Recipient="https://sp.example.com/acs" NotOnOrAfter="2026-11-14T12:05:00Z" InResponseTo="_req9"/></saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-11-14T11:59:00Z" NotOnOrAfter="2026-11-14T12:05:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-11-14T12:00:00Z" SessionIndex="_s1"/>
    <saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue><saml:AttributeValue>vpn-users &amp; friends</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#;

    const NOW: i64 = 1_794_657_660; // 2026-11-14T12:01:00Z

    fn exp() -> Expect {
        Expect {
            issuer: "https://idp.example.com".into(),
            audience: "https://sp.example.com".into(),
            recipient: "https://sp.example.com/acs".into(),
            skew_secs: 0,
        }
    }

    #[test]
    fn reads_fields_and_checks() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(XML);
        let r = inspect(&b64, &exp(), NOW).unwrap();
        assert_eq!(r.binding, "POST binding (Base64)");
        assert_eq!(r.message, "Response");
        assert_eq!(r.status, "Success");
        assert_eq!(r.name_id, "alice@example.com");
        assert_eq!(r.audiences, vec!["https://sp.example.com"]);
        assert_eq!(
            r.attributes,
            vec![(
                "groups".to_string(),
                vec!["admins".to_string(), "vpn-users & friends".to_string()]
            )]
        );
        assert_eq!(r.signatures.len(), 1);
        assert_eq!(r.signatures[0].on, "Assertion");
        assert!(r.signatures[0].weak);
        let fails: Vec<&str> = r
            .checks
            .iter()
            .filter(|c| c.status == "fail")
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(fails, vec!["Signature algorithm"]);
        let late = inspect(&b64, &exp(), NOW + 600).unwrap();
        assert!(
            late.checks
                .iter()
                .any(|c| c.name == "Conditions NotOnOrAfter" && c.status == "fail")
        );
        let wrong = inspect(
            &b64,
            &Expect {
                audience: "https://other.example.com".into(),
                ..exp()
            },
            NOW,
        )
        .unwrap();
        assert!(
            wrong
                .checks
                .iter()
                .any(|c| c.name == "Audience" && c.status == "fail")
        );
    }

    #[test]
    fn redirect_binding_and_query_string() {
        let req = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_q1" Destination="https://idp.example.com/sso"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer></samlp:AuthnRequest>"#;
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(req.as_bytes()).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(enc.finish().unwrap());
        let qs = format!(
            "https://idp.example.com/sso?SAMLRequest={}&RelayState=x",
            b64.replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        );
        let r = inspect(&qs, &Expect::default(), NOW).unwrap();
        assert!(r.binding.starts_with("Redirect binding"));
        assert_eq!(r.message, "AuthnRequest");
        assert_eq!(r.issuer, "https://sp.example.com");
        let sig = r.checks.iter().find(|c| c.name == "Signature").unwrap();
        assert_eq!(
            sig.status, "info",
            "an unsigned Redirect request is not a failure"
        );
        let signed = inspect(
            &format!("{qs}&SigAlg=x&Signature=abc"),
            &Expect::default(),
            NOW,
        )
        .unwrap();
        let sig = signed
            .checks
            .iter()
            .find(|c| c.name == "Signature")
            .unwrap();
        assert!(sig.detail.contains("signed in the URL"), "{}", sig.detail);
    }

    #[test]
    fn hostile_input() {
        assert!(inspect("not saml", &Expect::default(), NOW).is_err());
        assert!(inspect(&"a".repeat(MAX_INPUT + 1), &Expect::default(), NOW).is_err());
        let deep = format!("{}{}", "<a>".repeat(100), "</a>".repeat(100));
        assert!(
            inspect(&deep, &Expect::default(), NOW)
                .unwrap_err()
                .contains("deeply")
        );
        assert!(inspect("<a><b></a>", &Expect::default(), NOW).is_err());
        // Raw XML works too, and the external entity is not expanded.
        let r = inspect(XML, &Expect::default(), NOW).unwrap();
        assert_eq!(r.binding, "raw XML");
        assert!(!r.name_id.contains("root:"));
    }
}

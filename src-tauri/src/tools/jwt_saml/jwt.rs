//! JWT inspection. Three separate states: decoded (header and claims),
//! signature (only checked with a key the user supplies, for the algorithm
//! the user expects), and application checks (times, issuer, audience
//! against the user's expectations). Key URLs in the token are shown,
//! never fetched; `alg: none` is never treated as signed.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::{hmac, signature};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Longest token accepted.
pub const MAX_TOKEN: usize = 64 * 1024;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Expect {
    pub issuer: String,
    pub audience: String,
    /// Allowed clock skew in seconds for exp/nbf/iat.
    pub skew_secs: i64,
    /// HMAC secret, or a PEM public key or certificate.
    pub key: String,
    /// The algorithm the application expects, e.g. RS256. Empty means
    /// "whatever the header says", which is reported as a risk.
    pub alg: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SigState {
    /// No key given, so not checked.
    NotChecked,
    Valid,
    Invalid,
    /// `alg: none`: there is no signature.
    Unsigned,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub name: String,
    /// "pass", "fail" or "info".
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JwtResult {
    pub header: Value,
    pub claims: Value,
    pub alg: String,
    pub signature: SigState,
    pub signature_detail: String,
    pub checks: Vec<Check>,
    /// Header fields that point at keys elsewhere; never followed.
    pub key_refs: Vec<String>,
    pub times: Vec<(String, i64)>,
}

fn part(s: &str, what: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| format!("the {what} is not valid base64url"))
}

fn check(name: &str, status: &str, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status: status.into(),
        detail: detail.into(),
    }
}

fn rel(secs: i64) -> String {
    let a = secs.abs();
    let s = if a < 120 {
        format!("{a} s")
    } else if a < 7200 {
        format!("{} min", a / 60)
    } else if a < 172_800 {
        format!("{} h", a / 3600)
    } else {
        format!("{} days", a / 86_400)
    };
    if secs >= 0 {
        format!("in {s}")
    } else {
        format!("{s} ago")
    }
}

/// The raw public key bytes from a PEM SPKI public key or certificate:
/// PKCS#1 for RSA, the point for EC, 32 bytes for Ed25519.
fn public_key(pem_text: &str) -> Result<(String, Vec<u8>), String> {
    use x509_parser::pem::Pem;
    use x509_parser::prelude::FromDer;
    for pem in Pem::iter_from_buffer(pem_text.as_bytes()) {
        let p = pem.map_err(|e| format!("PEM error: {e}"))?;
        let spki_der = if p.label.contains("CERTIFICATE") {
            let (_, c) = x509_parser::prelude::X509Certificate::from_der(&p.contents)
                .map_err(|e| format!("not a certificate: {e}"))?;
            c.public_key().raw.to_vec()
        } else if p.label == "PUBLIC KEY" {
            p.contents.clone()
        } else if p.label.contains("PRIVATE KEY") {
            return Err(
                "that is a private key; paste the public key or certificate instead".into(),
            );
        } else {
            continue;
        };
        let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki_der)
            .map_err(|e| format!("not a public key: {e}"))?;
        let oid = spki.algorithm.algorithm.to_id_string();
        let kind = match oid.as_str() {
            "1.2.840.113549.1.1.1" => "RSA",
            "1.2.840.10045.2.1" => "EC",
            "1.3.101.112" => "Ed25519",
            other => return Err(format!("key algorithm {other} is not supported")),
        };
        return Ok((kind.into(), spki.subject_public_key.data.to_vec()));
    }
    Err("no PEM public key or certificate found".into())
}

fn verify(alg: &str, signing_input: &[u8], sig: &[u8], key: &str) -> Result<bool, String> {
    let hmac_alg = match alg {
        "HS256" => Some(hmac::HMAC_SHA256),
        "HS384" => Some(hmac::HMAC_SHA384),
        "HS512" => Some(hmac::HMAC_SHA512),
        _ => None,
    };
    if let Some(a) = hmac_alg {
        if key.contains("-----BEGIN") {
            return Err("an HMAC algorithm needs the shared secret, not a public key (this is the classic algorithm-confusion mistake)".into());
        }
        let k = hmac::Key::new(a, key.as_bytes());
        return Ok(hmac::verify(&k, signing_input, sig).is_ok());
    }
    let (kind, raw) = public_key(key)?;
    let params: &dyn signature::VerificationAlgorithm = match (alg, kind.as_str()) {
        ("RS256", "RSA") => &signature::RSA_PKCS1_2048_8192_SHA256,
        ("RS384", "RSA") => &signature::RSA_PKCS1_2048_8192_SHA384,
        ("RS512", "RSA") => &signature::RSA_PKCS1_2048_8192_SHA512,
        ("PS256", "RSA") => &signature::RSA_PSS_2048_8192_SHA256,
        ("PS384", "RSA") => &signature::RSA_PSS_2048_8192_SHA384,
        ("PS512", "RSA") => &signature::RSA_PSS_2048_8192_SHA512,
        ("ES256", "EC") => &signature::ECDSA_P256_SHA256_FIXED,
        ("ES384", "EC") => &signature::ECDSA_P384_SHA384_FIXED,
        ("EdDSA", "Ed25519") => &signature::ED25519,
        (a, k) => {
            return Err(format!(
                "algorithm {a} does not match a {k} key, or is not supported"
            ));
        }
    };
    Ok(signature::UnparsedPublicKey::new(params, &raw)
        .verify(signing_input, sig)
        .is_ok())
}

/// Inspect a JWT. `now` is Unix seconds.
pub fn inspect(token: &str, exp: &Expect, now: i64) -> Result<JwtResult, String> {
    let t: String = token
        .trim()
        .trim_start_matches("Bearer ")
        .trim_start_matches("bearer ")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if t.len() > MAX_TOKEN {
        return Err("token longer than 64 KB".into());
    }
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() == 5 {
        return Err("this is an encrypted JWT (JWE, five parts); its claims cannot be read without the decryption key".into());
    }
    if parts.len() != 3 {
        return Err(format!(
            "a JWT has three dot-separated parts; this has {}",
            parts.len()
        ));
    }
    let header: Value = serde_json::from_slice(&part(parts[0], "header")?)
        .map_err(|_| "the header is not JSON".to_string())?;
    let claims_raw = part(parts[1], "payload")?;
    let claims: Value = serde_json::from_slice(&claims_raw)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&claims_raw).into_owned()));
    let sig = if parts[2].is_empty() {
        Vec::new()
    } else {
        part(parts[2], "signature")?
    };
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let mut key_refs = Vec::new();
    for k in ["jku", "x5u", "jwk", "x5c", "kid"] {
        if let Some(v) = header.get(k) {
            let shown = v
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| "(embedded)".into());
            key_refs.push(format!("{k}: {shown}"));
        }
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let (signature, signature_detail) = if alg.eq_ignore_ascii_case("none") {
        (
            SigState::Unsigned,
            "alg is \"none\": the token carries no signature. Applications must reject it."
                .to_string(),
        )
    } else if exp.key.trim().is_empty() {
        (SigState::NotChecked, "No key given. Paste the HMAC secret, or the issuer's public key or certificate, to check the signature.".to_string())
    } else if !exp.alg.trim().is_empty() && !exp.alg.trim().eq_ignore_ascii_case(&alg) {
        (
            SigState::Invalid,
            format!(
                "The header says {alg} but the expected algorithm is {}. Accepting a header-chosen algorithm is how algorithm-confusion attacks work.",
                exp.alg.trim()
            ),
        )
    } else {
        match verify(&alg, signing_input.as_bytes(), &sig, exp.key.trim()) {
            Ok(true) => (
                SigState::Valid,
                format!("{alg} signature verifies with the key given."),
            ),
            Ok(false) => (
                SigState::Invalid,
                format!("{alg} signature does not verify with the key given."),
            ),
            Err(e) => (SigState::Unsupported, e),
        }
    };

    let mut checks = Vec::new();
    if exp.alg.trim().is_empty() && signature == SigState::Valid {
        checks.push(check("Algorithm", "info", format!("Verified with the header's own algorithm ({alg}); set the expected algorithm to pin it.")));
    }
    let skew = exp.skew_secs.clamp(0, 3600);
    let mut times = Vec::new();
    let num = |k: &str| claims.get(k).and_then(Value::as_i64);
    if let Some(e) = num("exp") {
        times.push(("exp".to_string(), e));
        if now > e + skew {
            checks.push(check(
                "Expiry (exp)",
                "fail",
                format!("expired {}", rel(e - now)),
            ));
        } else {
            checks.push(check(
                "Expiry (exp)",
                "pass",
                format!("expires {}", rel(e - now)),
            ));
        }
    } else {
        checks.push(check(
            "Expiry (exp)",
            "info",
            "no exp claim: the token never expires on its own",
        ));
    }
    if let Some(n) = num("nbf") {
        times.push(("nbf".to_string(), n));
        if now + skew < n {
            checks.push(check(
                "Not before (nbf)",
                "fail",
                format!("not valid until {}", rel(n - now)),
            ));
        } else {
            checks.push(check(
                "Not before (nbf)",
                "pass",
                format!("valid since {}", rel(n - now)),
            ));
        }
    }
    if let Some(i) = num("iat") {
        times.push(("iat".to_string(), i));
        if i > now + skew {
            checks.push(check(
                "Issued at (iat)",
                "fail",
                format!("issued in the future ({}); check clocks", rel(i - now)),
            ));
        }
    }
    if !exp.issuer.trim().is_empty() {
        let iss = claims.get("iss").and_then(Value::as_str).unwrap_or("");
        let ok = iss == exp.issuer.trim();
        checks.push(check(
            "Issuer (iss)",
            if ok { "pass" } else { "fail" },
            if ok {
                format!("matches {iss}")
            } else {
                format!("token has \"{iss}\", expected \"{}\"", exp.issuer.trim())
            },
        ));
    }
    if !exp.audience.trim().is_empty() {
        let want = exp.audience.trim();
        let auds: Vec<String> = match claims.get("aud") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        };
        let ok = auds.iter().any(|a| a == want);
        checks.push(check(
            "Audience (aud)",
            if ok { "pass" } else { "fail" },
            if ok {
                format!("includes {want}")
            } else {
                format!("token audience {auds:?} does not include \"{want}\"")
            },
        ));
    }
    Ok(JwtResult {
        header,
        claims,
        alg,
        signature,
        signature_detail,
        checks,
        key_refs,
        times,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(v: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(v)
    }

    fn hs256(claims: &str, secret: &str) -> String {
        let input = format!(
            "{}.{}",
            b64(br#"{"alg":"HS256","typ":"JWT"}"#),
            b64(claims.as_bytes())
        );
        let k = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        format!("{input}.{}", b64(hmac::sign(&k, input.as_bytes()).as_ref()))
    }

    const NOW: i64 = 1_794_614_400;

    #[test]
    fn hmac_and_checks() {
        let tok = hs256(
            &format!(
                r#"{{"iss":"https://idp.example.com","aud":["api://one","api://two"],"sub":"alice","exp":{},"nbf":{},"iat":{}}}"#,
                NOW + 3600,
                NOW - 60,
                NOW - 60
            ),
            "s3cret",
        );
        let ok = inspect(
            &tok,
            &Expect {
                key: "s3cret".into(),
                issuer: "https://idp.example.com".into(),
                audience: "api://two".into(),
                alg: "HS256".into(),
                ..Default::default()
            },
            NOW,
        )
        .unwrap();
        assert_eq!(ok.signature, SigState::Valid);
        assert!(
            ok.checks.iter().all(|c| c.status != "fail"),
            "{:?}",
            ok.checks
        );
        assert_eq!(ok.claims["sub"], "alice");
        let bad = inspect(
            &tok,
            &Expect {
                key: "wrong".into(),
                ..Default::default()
            },
            NOW,
        )
        .unwrap();
        assert_eq!(bad.signature, SigState::Invalid);
        let late = inspect(
            &tok,
            &Expect {
                audience: "api://three".into(),
                ..Default::default()
            },
            NOW + 7200,
        )
        .unwrap();
        assert_eq!(late.signature, SigState::NotChecked);
        assert!(
            late.checks
                .iter()
                .any(|c| c.name.starts_with("Expiry") && c.status == "fail")
        );
        assert!(
            late.checks
                .iter()
                .any(|c| c.name.starts_with("Audience") && c.status == "fail")
        );
    }

    #[test]
    fn alg_confusion_and_none() {
        let tok = hs256(r#"{"sub":"x"}"#, "s");
        let pinned = inspect(
            &tok,
            &Expect {
                key: "s".into(),
                alg: "RS256".into(),
                ..Default::default()
            },
            NOW,
        )
        .unwrap();
        assert_eq!(pinned.signature, SigState::Invalid);
        assert!(pinned.signature_detail.contains("algorithm-confusion"));
        let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----";
        let r = inspect(
            &tok,
            &Expect {
                key: pem.into(),
                ..Default::default()
            },
            NOW,
        )
        .unwrap();
        assert_eq!(r.signature, SigState::Unsupported);
        assert!(r.signature_detail.contains("shared secret"));
        let none = format!("{}.{}.", b64(br#"{"alg":"none"}"#), b64(br#"{"sub":"x"}"#));
        assert_eq!(
            inspect(
                &none,
                &Expect {
                    key: "anything".into(),
                    ..Default::default()
                },
                NOW
            )
            .unwrap()
            .signature,
            SigState::Unsigned
        );
    }

    #[test]
    fn ed25519_with_public_key() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(kp.public_key().as_ref());
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            base64::engine::general_purpose::STANDARD.encode(&spki)
        );
        let input = format!(
            "{}.{}",
            b64(br#"{"alg":"EdDSA","kid":"k1","jku":"https://evil.example/keys"}"#),
            b64(br#"{"sub":"bob"}"#)
        );
        let tok = format!("{input}.{}", b64(kp.sign(input.as_bytes()).as_ref()));
        let r = inspect(
            &tok,
            &Expect {
                key: pem.clone(),
                alg: "EdDSA".into(),
                ..Default::default()
            },
            NOW,
        )
        .unwrap();
        assert_eq!(r.signature, SigState::Valid, "{}", r.signature_detail);
        assert!(
            r.key_refs
                .iter()
                .any(|k| k.starts_with("jku: https://evil.example"))
        );
        let tampered = tok.replace(&b64(br#"{"sub":"bob"}"#), &b64(br#"{"sub":"eve"}"#));
        assert_eq!(
            inspect(
                &tampered,
                &Expect {
                    key: pem,
                    ..Default::default()
                },
                NOW
            )
            .unwrap()
            .signature,
            SigState::Invalid
        );
    }

    #[test]
    fn malformed() {
        assert!(inspect("abc", &Expect::default(), NOW).is_err());
        assert!(
            inspect("a.b.c.d.e", &Expect::default(), NOW)
                .unwrap_err()
                .contains("JWE")
        );
        assert!(inspect("!!!.e30.", &Expect::default(), NOW).is_err());
        assert!(inspect(&"a".repeat(MAX_TOKEN + 1), &Expect::default(), NOW).is_err());
        let priv_key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
        let tok = format!(
            "{}.{}.{}",
            b64(br#"{"alg":"RS256"}"#),
            b64(b"{}"),
            b64(b"sig")
        );
        let r = inspect(
            &tok,
            &Expect {
                key: priv_key.into(),
                ..Default::default()
            },
            NOW,
        )
        .unwrap();
        assert_eq!(r.signature, SigState::Unsupported);
    }
}

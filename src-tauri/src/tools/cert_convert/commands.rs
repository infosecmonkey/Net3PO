//! Tauri commands for the certificate converter. Inputs travel as base64;
//! nothing is stored. Private key bytes never go back to the UI except as a
//! file the user chose to save.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use super::core::{self, Input, Output};
use crate::tools::tls_inspector::cert::{self as tls_cert, CertInfo, CsrInfo};

/// One input as sent by the UI.
#[derive(Debug, Deserialize, Serialize)]
pub struct InputDto {
    pub name: String,
    /// Base64 of the bytes.
    pub data: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertView {
    pub index: usize,
    pub source: String,
    /// "Leaf", "Intermediate", "Root", or "Not in chain".
    pub role: String,
    pub info: Option<Box<CertInfo>>,
    pub error: Option<String>,
    /// Indexes of keys that match this certificate.
    pub keys: Vec<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyView {
    pub index: usize,
    pub source: String,
    pub description: String,
    /// Certificates this key matches.
    pub certs: Vec<usize>,
    /// The public key could be worked out, so matching was checked.
    pub checkable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CsrView {
    pub source: String,
    pub info: Option<Box<CsrInfo>>,
    pub error: Option<String>,
    /// Keys that match this CSR.
    pub keys: Vec<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub certs: Vec<CertView>,
    pub keys: Vec<KeyView>,
    pub csrs: Vec<CsrView>,
    /// Certificate indexes, leaf first.
    pub chain: Vec<usize>,
    pub ends_at_root: bool,
    pub missing_issuer: Option<String>,
    pub warnings: Vec<String>,
    pub needs_password: bool,
    pub wrong_password: bool,
}

#[derive(Serialize)]
pub struct FileData {
    pub name: String,
    pub data: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Exported {
    /// The text, for certificate outputs without a key and no path.
    pub text: Option<String>,
    pub bytes: usize,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn decode_inputs(inputs: Vec<InputDto>) -> Result<Vec<Input>, String> {
    if inputs.len() > core::MAX_INPUTS {
        return Err(format!("at most {} files at a time", core::MAX_INPUTS));
    }
    inputs
        .into_iter()
        .map(|i| {
            if i.data.len() > core::MAX_INPUT * 4 / 3 + 8 {
                return Err(format!("{}: larger than 10 MB", i.name));
            }
            let data = STANDARD
                .decode(i.data.as_bytes())
                .map_err(|_| format!("{}: bad data", i.name))?;
            let name: String = i
                .name
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            Ok(Input { name, data })
        })
        .collect()
}

/// Read a file chosen in the open dialog.
#[tauri::command]
pub fn cert_read_file(path: String) -> Result<FileData, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    if meta.len() > core::MAX_INPUT as u64 {
        return Err(format!("{path} is larger than 10 MB"));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    let name = std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or(path);
    Ok(FileData {
        name,
        data: STANDARD.encode(bytes),
    })
}

/// Read everything in the inputs and describe it.
#[tauri::command]
pub async fn cert_inspect(inputs: Vec<InputDto>, password: String) -> Result<Summary, String> {
    let inputs = decode_inputs(inputs)?;
    tokio::task::spawn_blocking(move || summarize(&core::parse(&inputs, &password)))
        .await
        .map_err(|e| e.to_string())
}

fn summarize(p: &core::Parsed) -> Summary {
    let chain = core::chain(p);
    let now = now_ms();
    let key_certs: Vec<Vec<usize>> = p
        .keys
        .iter()
        .map(|k| core::key_matches(&p.certs, &k.value))
        .collect();
    let n = chain.order.len();
    let certs = p
        .certs
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let role = match chain.order.iter().position(|&j| j == i) {
                Some(pos) if pos == n - 1 && chain.ends_at_root => {
                    if n == 1 {
                        "Self-signed"
                    } else {
                        "Root"
                    }
                }
                Some(0) => "Leaf",
                Some(_) => "Intermediate",
                None => "Not in chain",
            };
            let (info, error) = match tls_cert::decode_cert(&c.value, now) {
                Ok(info) => (Some(Box::new(info)), None),
                Err(e) => (None, Some(e)),
            };
            CertView {
                index: i,
                source: c.source.clone(),
                role: role.into(),
                info,
                error,
                keys: key_certs
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| m.contains(&i))
                    .map(|(k, _)| k)
                    .collect(),
            }
        })
        .collect();
    let keys = p
        .keys
        .iter()
        .enumerate()
        .map(|(i, k)| KeyView {
            index: i,
            source: k.source.clone(),
            description: k.value.description.clone(),
            certs: key_certs[i].clone(),
            checkable: k.value.public.is_some(),
        })
        .collect();
    let csrs = p
        .csrs
        .iter()
        .map(|c| {
            let public = core::csr_public(&c.value);
            let (info, error) = match tls_cert::decode_csr(&c.value) {
                Ok(info) => (Some(Box::new(info)), None),
                Err(e) => (None, Some(e)),
            };
            CsrView {
                source: c.source.clone(),
                info,
                error,
                keys: p
                    .keys
                    .iter()
                    .enumerate()
                    .filter(|(_, k)| public.is_some() && k.value.public == public)
                    .map(|(i, _)| i)
                    .collect(),
            }
        })
        .collect();
    Summary {
        certs,
        keys,
        csrs,
        chain: chain.order,
        ends_at_root: chain.ends_at_root,
        missing_issuer: chain.missing_issuer,
        warnings: p.warnings.clone(),
        needs_password: p.needs_password,
        wrong_password: p.wrong_password,
    }
}

/// Produce an output. With `path`, writes the file there (chosen in the
/// save dialog). Without, returns the text; only allowed for certificate
/// text outputs, so private keys only ever leave as a file.
#[tauri::command]
pub async fn cert_export(
    inputs: Vec<InputDto>,
    password: String,
    output: Output,
    path: Option<String>,
) -> Result<Exported, String> {
    let inputs = decode_inputs(inputs)?;
    if path.is_none() && (output.has_key() || !output.is_text()) {
        return Err("choose a file to save this output".into());
    }
    tokio::task::spawn_blocking(move || {
        let p = core::parse(&inputs, &password);
        let bytes = core::export(&p, &output).map_err(|e| e.to_string())?;
        match path {
            Some(path) => {
                std::fs::write(&path, &bytes)
                    .map_err(|e| format!("could not write {path}: {e}"))?;
                Ok(Exported {
                    text: None,
                    bytes: bytes.len(),
                })
            }
            None => Ok(Exported {
                bytes: bytes.len(),
                text: Some(String::from_utf8_lossy(&bytes).into_owned()),
            }),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_of_real_fixtures() {
        let ca = include_str!("../tls_inspector/testdata/ca.pem");
        let leaf = include_str!("../tls_inspector/testdata/leaf.pem");
        let inputs = decode_inputs(vec![
            InputDto {
                name: "ca.pem".into(),
                data: STANDARD.encode(ca),
            },
            InputDto {
                name: "leaf.pem".into(),
                data: STANDARD.encode(leaf),
            },
        ])
        .unwrap();
        let s = summarize(&core::parse(&inputs, ""));
        assert_eq!(s.certs.len(), 2);
        let roles: Vec<&str> = s.chain.iter().map(|&i| s.certs[i].role.as_str()).collect();
        assert_eq!(roles, ["Leaf", "Root"]);
        assert!(s.certs.iter().all(|c| c.info.is_some()));
    }

    #[test]
    fn rejects_bad_inputs() {
        assert!(
            decode_inputs(vec![InputDto {
                name: "x".into(),
                data: "!!".into()
            }])
            .is_err()
        );
        let many = (0..=core::MAX_INPUTS)
            .map(|i| InputDto {
                name: i.to_string(),
                data: String::new(),
            })
            .collect();
        assert!(decode_inputs(many).is_err());
    }

    #[tokio::test]
    async fn key_outputs_need_a_path() {
        let r = cert_export(vec![], String::new(), Output::KeyPkcs8Pem, None).await;
        assert!(r.unwrap_err().contains("choose a file"));
        let r = cert_export(vec![], String::new(), Output::DerLeaf, None).await;
        assert!(r.is_err());
    }
}

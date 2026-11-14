//! Tauri commands for the JWT/SAML inspector. Tokens and keys are never
//! logged or stored.

use super::{jwt, saml};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[tauri::command]
pub fn jwt_inspect(token: String, expect: jwt::Expect) -> Result<jwt::JwtResult, String> {
    jwt::inspect(&token, &expect, now())
}

#[tauri::command]
pub fn saml_inspect(input: String, expect: saml::Expect) -> Result<saml::SamlResult, String> {
    saml::inspect(&input, &expect, now())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlScan {
    /// Every SAML message found in the input.
    pub found: Vec<super::capture::Found>,
    pub selected: usize,
    pub result: Option<saml::SamlResult>,
    pub error: Option<String>,
}

/// Find SAML messages in any capture (SAML-tracer, HAR, HTML, URL,
/// FortiGate samld debug, Base64) and inspect the one at `pick`.
#[tauri::command]
pub async fn saml_scan(
    input: String,
    expect: saml::Expect,
    pick: usize,
) -> Result<SamlScan, String> {
    tokio::task::spawn_blocking(move || {
        if input.len() > super::capture::MAX_CAPTURE {
            return Err("capture larger than 32 MB".to_string());
        }
        let found = super::capture::find(&input);
        if found.is_empty() {
            // Fall back to treating the whole input as one message.
            return match saml::inspect(&input, &expect, now()) {
                Ok(r) => Ok(SamlScan { found, selected: 0, result: Some(r), error: None }),
                Err(_) => Ok(SamlScan {
                    found,
                    selected: 0,
                    result: None,
                    error: Some("No SAML message found. Paste a SAML-tracer export, a HAR file, FortiGate samld debug output, a URL with SAMLRequest=, a SAMLResponse value, or the XML.".into()),
                }),
            };
        }
        let selected = pick.min(found.len() - 1);
        let (result, error) = match saml::inspect(&found[selected].data, &expect, now()) {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e)),
        };
        Ok(SamlScan { found, selected, result, error })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Read a capture file (SAML-tracer JSON, HAR, debug log) for scanning.
#[tauri::command]
pub async fn saml_read_file(path: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let meta = std::fs::metadata(&path).map_err(|e| format!("could not read {path}: {e}"))?;
        if meta.len() > super::capture::MAX_CAPTURE as u64 {
            return Err("file larger than 32 MB".into());
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("could not read {path}: {e}"))?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    })
    .await
    .map_err(|e| e.to_string())?
}

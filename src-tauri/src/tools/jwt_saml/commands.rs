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

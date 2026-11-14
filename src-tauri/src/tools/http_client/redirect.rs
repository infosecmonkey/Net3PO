//! Redirect policy, matching what browsers do: 303 always becomes GET
//! (HEAD stays HEAD), 301/302 turn POST into GET, 307/308 keep the method
//! and body. Credentials are never forwarded to a different origin.

use super::url::Url;
use super::wire::CREDENTIAL_HEADERS;

pub fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Method for the next hop and whether the body is kept.
pub fn next_method(status: u16, method: &str) -> (String, bool) {
    match status {
        303 if method != "HEAD" => ("GET".into(), false),
        301 | 302 if method == "POST" => ("GET".into(), false),
        _ => (method.to_string(), true),
    }
}

/// Headers for the next hop. Credential headers are dropped when the
/// origin changes; the names dropped are returned for display.
pub fn next_headers(
    from: &Url,
    to: &Url,
    headers: &[(String, String)],
    keep_body: bool,
) -> (Vec<(String, String)>, Vec<String>) {
    let cross = !from.same_origin(to);
    let mut dropped = Vec::new();
    let kept = headers
        .iter()
        .filter(|(n, _)| {
            let lower = n.to_ascii_lowercase();
            if cross && CREDENTIAL_HEADERS.contains(&lower.as_str()) {
                dropped.push(n.clone());
                return false;
            }
            // Body headers go with the body.
            keep_body || !(lower == "content-type" || lower.starts_with("content-"))
        })
        .cloned()
        .collect();
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::super::url::parse;
    use super::*;

    #[test]
    fn methods() {
        assert_eq!(next_method(303, "POST"), ("GET".into(), false));
        assert_eq!(next_method(303, "HEAD"), ("HEAD".into(), true));
        assert_eq!(next_method(302, "POST"), ("GET".into(), false));
        assert_eq!(next_method(301, "PUT"), ("PUT".into(), true));
        assert_eq!(next_method(307, "POST"), ("POST".into(), true));
        assert_eq!(next_method(308, "DELETE"), ("DELETE".into(), true));
        assert!(is_redirect(308) && !is_redirect(304) && !is_redirect(300));
    }

    #[test]
    fn credentials_stay_on_origin() {
        let h = vec![
            ("Authorization".to_string(), "Bearer x".to_string()),
            ("Cookie".to_string(), "a=b".to_string()),
            ("X-Trace".to_string(), "1".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let a = parse("https://api.example.com/a").unwrap();
        let same = parse("https://api.example.com/b").unwrap();
        let other = parse("https://login.example.net/").unwrap();
        let (kept, dropped) = next_headers(&a, &same, &h, true);
        assert_eq!((kept.len(), dropped.len()), (4, 0));
        let (kept, dropped) = next_headers(&a, &other, &h, false);
        assert_eq!(dropped, vec!["Authorization", "Cookie"]);
        assert_eq!(kept, vec![("X-Trace".to_string(), "1".to_string())]);
        // A scheme change is a different origin too.
        let plain = parse("http://api.example.com/a").unwrap();
        assert_eq!(next_headers(&a, &plain, &h, true).1.len(), 2);
    }
}

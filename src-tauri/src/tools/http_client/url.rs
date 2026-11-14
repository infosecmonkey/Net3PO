//! Minimal URL handling for the HTTP troubleshooter: parse `http`/`https`
//! URLs, compare origins and resolve redirect `Location` values. Userinfo
//! is refused so credentials never travel in a URL by accident.

use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    /// Lowercase hostname or IP (no brackets).
    pub host: String,
    pub port: u16,
    /// Path plus query, always starting with `/`. Fragments are dropped.
    pub target: String,
}

impl Url {
    pub fn default_port(&self) -> u16 {
        if self.https { 443 } else { 80 }
    }

    /// `Host` header value: the port only when it is not the default.
    pub fn host_header(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.default_port() {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }

    /// Scheme, host and port: what makes two URLs the same origin.
    pub fn same_origin(&self, other: &Url) -> bool {
        self.https == other.https && self.host == other.host && self.port == other.port
    }

    /// Path without the query, for resolving relative references.
    fn dir(&self) -> &str {
        let path = self.target.split('?').next().unwrap_or("/");
        match path.rfind('/') {
            Some(i) => &path[..=i],
            None => "/",
        }
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}{}",
            if self.https { "https" } else { "http" },
            self.host_header(),
            self.target
        )
    }
}

fn valid_host(h: &str) -> bool {
    h.parse::<IpAddr>().is_ok()
        || (h.len() <= 253
            && h.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }))
}

/// Percent-encode characters that may not appear raw in a request target.
fn clean_target(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    for c in t.chars() {
        if c.is_ascii_graphic() {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

/// Parse an absolute URL. A missing scheme means `https://`.
pub fn parse(input: &str) -> Result<Url, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("enter a URL".into());
    }
    if s.len() > 8192 {
        return Err("URL longer than 8 KB".into());
    }
    let (https, rest) = match s.split_once("://") {
        Some((scheme, rest)) => match scheme.to_ascii_lowercase().as_str() {
            "https" => (true, rest),
            "http" => (false, rest),
            other => return Err(format!("unsupported scheme {other}: use http or https")),
        },
        None => (true, s),
    };
    let rest = rest.split('#').next().unwrap_or("");
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, target) = rest.split_at(split);
    if authority.contains('@') {
        return Err(
            "credentials in the URL are not sent; use an Authorization header instead".into(),
        );
    }
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let (h, tail) = r.split_once(']').ok_or("unclosed [ in host")?;
        (h.to_string(), tail.strip_prefix(':'))
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), Some(p))
    } else {
        (authority.to_string(), None)
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty() || !valid_host(&host) {
        return Err(format!("not a valid host: {authority}"));
    }
    let default = if https { 443 } else { 80 };
    let port = match port {
        Some("") | None => default,
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .ok_or("invalid port")?,
    };
    let target = if target.is_empty() {
        "/".to_string()
    } else if target.starts_with('?') {
        format!("/{target}")
    } else {
        target.to_string()
    };
    Ok(Url {
        https,
        host,
        port,
        target: clean_target(&target),
    })
}

/// Resolve a `Location` header against the URL that returned it.
pub fn resolve(base: &Url, location: &str) -> Result<Url, String> {
    let loc = location.trim();
    if loc.is_empty() {
        return Err("empty Location header".into());
    }
    if loc.contains("://") {
        return parse(loc);
    }
    if let Some(rest) = loc.strip_prefix("//") {
        return parse(&format!(
            "{}://{rest}",
            if base.https { "https" } else { "http" }
        ));
    }
    let loc = loc.split('#').next().unwrap_or("");
    let target = if loc.starts_with('/') {
        loc.to_string()
    } else if loc.starts_with('?') {
        format!("{}{loc}", base.target.split('?').next().unwrap_or("/"))
    } else {
        format!("{}{loc}", base.dir())
    };
    Ok(Url {
        target: clean_target(&normalize_dots(&target)),
        ..base.clone()
    })
}

/// Remove `.` and `..` segments from the path part.
fn normalize_dots(target: &str) -> String {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    let mut out: Vec<&str> = Vec::new();
    let segs: Vec<&str> = path.split('/').collect();
    for (i, seg) in segs.iter().enumerate() {
        match *seg {
            "." => {
                if i == segs.len() - 1 {
                    out.push("");
                }
            }
            ".." => {
                if out.len() > 1 {
                    out.pop();
                }
                if i == segs.len() - 1 {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    let mut p = out.join("/");
    if !p.starts_with('/') {
        p.insert(0, '/');
    }
    match query {
        Some(q) => format!("{p}?{q}"),
        None => p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        let u = parse("Example.com").unwrap();
        assert_eq!(
            (u.https, u.host.as_str(), u.port, u.target.as_str()),
            (true, "example.com", 443, "/")
        );
        let u = parse("http://example.com:8080/a/b?c=d#frag").unwrap();
        assert_eq!(
            (u.https, u.port, u.target.as_str()),
            (false, 8080, "/a/b?c=d")
        );
        assert_eq!(u.host_header(), "example.com:8080");
        let u = parse("https://[2001:db8::1]/x").unwrap();
        assert_eq!(u.host, "2001:db8::1");
        assert_eq!(u.host_header(), "[2001:db8::1]");
        assert_eq!(parse("https://example.com?q=1").unwrap().target, "/?q=1");
        assert_eq!(parse("https://example.com/a b").unwrap().target, "/a%20b");
        assert!(parse("ftp://example.com").is_err());
        assert!(
            parse("https://user:pw@example.com")
                .unwrap_err()
                .contains("credentials")
        );
        assert!(parse("https://exa mple.com").is_err());
        assert!(parse("https://example.com:70000").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn origins() {
        let a = parse("https://example.com/a").unwrap();
        assert!(a.same_origin(&parse("https://example.com:443/b").unwrap()));
        assert!(!a.same_origin(&parse("http://example.com/a").unwrap()));
        assert!(!a.same_origin(&parse("https://www.example.com/a").unwrap()));
        assert!(!a.same_origin(&parse("https://example.com:8443/a").unwrap()));
    }

    #[test]
    fn redirects() {
        let base = parse("https://example.com/dir/page?x=1").unwrap();
        let r = |l: &str| resolve(&base, l).unwrap().to_string();
        assert_eq!(r("/other"), "https://example.com/other");
        assert_eq!(r("next"), "https://example.com/dir/next");
        assert_eq!(r("../up"), "https://example.com/up");
        assert_eq!(r("./same?y=2"), "https://example.com/dir/same?y=2");
        assert_eq!(r("?z=3"), "https://example.com/dir/page?z=3");
        assert_eq!(r("//cdn.example.net/a"), "https://cdn.example.net/a");
        assert_eq!(r("http://example.com/plain"), "http://example.com/plain");
        assert_eq!(r("/a/../../b"), "https://example.com/b");
        assert!(resolve(&base, "").is_err());
        assert!(resolve(&base, "javascript://x").is_err());
    }
}

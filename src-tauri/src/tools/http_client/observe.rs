//! Header observations: contextual notes about security and caching
//! headers on a response. They explain what is present or missing; they are
//! not a security rating and say nothing about the application itself.

use serde::Serialize;

use super::wire::Response;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Sev {
    Pass,
    Info,
    Warn,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub severity: Sev,
    pub header: String,
    pub title: String,
    pub detail: String,
}

fn obs(
    severity: Sev,
    header: &str,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> Observation {
    Observation {
        severity,
        header: header.into(),
        title: title.into(),
        detail: detail.into(),
    }
}

fn directive<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    value.split(';').map(str::trim).find_map(|d| {
        let (k, v) = d.split_once('=').unwrap_or((d, ""));
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().trim_matches('"'))
    })
}

fn hsts(r: &Response, https: bool, out: &mut Vec<Observation>) {
    let Some(v) = r.header("strict-transport-security") else {
        if https {
            out.push(obs(Sev::Warn, "Strict-Transport-Security", "No HSTS", "Browsers may still try plain HTTP first on later visits. Expected on HTTPS sites that never need HTTP."));
        }
        return;
    };
    if !https {
        out.push(obs(
            Sev::Info,
            "Strict-Transport-Security",
            "HSTS sent over plain HTTP",
            "Browsers ignore HSTS received over HTTP; it only counts on HTTPS responses.",
        ));
        return;
    }
    let age: u64 = directive(v, "max-age")
        .and_then(|a| a.parse().ok())
        .unwrap_or(0);
    let subs = directive(v, "includeSubDomains").is_some();
    let preload = directive(v, "preload").is_some();
    if age == 0 {
        out.push(obs(
            Sev::Warn,
            "Strict-Transport-Security",
            "HSTS max-age is 0",
            "max-age=0 tells browsers to forget HSTS for this host.",
        ));
    } else if age < 15_552_000 {
        out.push(obs(
            Sev::Info,
            "Strict-Transport-Security",
            format!("HSTS for {} days", age / 86_400),
            "Common practice is at least 180 days; preload lists require one year.",
        ));
    } else {
        out.push(obs(
            Sev::Pass,
            "Strict-Transport-Security",
            format!(
                "HSTS for {} days{}{}",
                age / 86_400,
                if subs { ", includeSubDomains" } else { "" },
                if preload { ", preload" } else { "" }
            ),
            "",
        ));
    }
}

fn csp(r: &Response, out: &mut Vec<Observation>) {
    let ct = r.header("content-type").unwrap_or("").to_ascii_lowercase();
    let html = ct.contains("text/html");
    let Some(v) = r.header("content-security-policy") else {
        if r.header("content-security-policy-report-only").is_some() {
            out.push(obs(
                Sev::Info,
                "Content-Security-Policy-Report-Only",
                "CSP in report-only mode",
                "Violations are reported but not blocked.",
            ));
        } else if html {
            out.push(obs(
                Sev::Info,
                "Content-Security-Policy",
                "No CSP on an HTML page",
                "A CSP limits where scripts and other content can load from, reducing XSS impact.",
            ));
        }
        return;
    };
    let lower = v.to_ascii_lowercase();
    let mut weak = Vec::new();
    if lower.contains("'unsafe-inline'")
        && !lower.contains("'nonce-")
        && !lower.contains("'strict-dynamic'")
    {
        weak.push("'unsafe-inline'");
    }
    if lower.contains("'unsafe-eval'") {
        weak.push("'unsafe-eval'");
    }
    if lower.split([';', ' ']).any(|t| t == "*") {
        weak.push("a * source");
    }
    if weak.is_empty() {
        out.push(obs(Sev::Pass, "Content-Security-Policy", "CSP present", ""));
    } else {
        out.push(obs(
            Sev::Info,
            "Content-Security-Policy",
            format!("CSP allows {}", weak.join(", ")),
            "These weaken the protection a CSP gives against injected scripts.",
        ));
    }
}

fn framing(r: &Response, out: &mut Vec<Observation>) {
    let ct = r.header("content-type").unwrap_or("").to_ascii_lowercase();
    if !ct.contains("text/html") {
        return;
    }
    let fa = r
        .header("content-security-policy")
        .is_some_and(|c| c.to_ascii_lowercase().contains("frame-ancestors"));
    match r.header("x-frame-options") {
        Some(v) => out.push(obs(Sev::Pass, "X-Frame-Options", format!("Framing limited: {v}"), "")),
        None if fa => out.push(obs(Sev::Pass, "Content-Security-Policy", "Framing limited by frame-ancestors", "")),
        None => out.push(obs(Sev::Info, "X-Frame-Options", "Page can be framed by any site", "Without X-Frame-Options or CSP frame-ancestors, clickjacking is possible if the page has sensitive actions.")),
    }
}

fn simple(r: &Response, out: &mut Vec<Observation>) {
    match r.header("x-content-type-options") {
        Some(v) if v.trim().eq_ignore_ascii_case("nosniff") => {
            out.push(obs(Sev::Pass, "X-Content-Type-Options", "nosniff set", ""))
        }
        _ => out.push(obs(
            Sev::Info,
            "X-Content-Type-Options",
            "nosniff not set",
            "Browsers may guess content types, which can turn uploads into scripts.",
        )),
    }
    if r.header("referrer-policy").is_none() {
        out.push(obs(
            Sev::Info,
            "Referrer-Policy",
            "No Referrer-Policy",
            "Browsers default to strict-origin-when-cross-origin, which is usually fine.",
        ));
    }
    for name in ["server", "x-powered-by", "x-aspnet-version"] {
        if let Some(v) = r.header(name)
            && v.chars().any(|c| c.is_ascii_digit())
        {
            out.push(obs(Sev::Info, name, format!("Version disclosed: {v}"), "Version strings help attackers match known vulnerabilities; they may also be stale or faked."));
        }
    }
}

fn cookies(r: &Response, https: bool, out: &mut Vec<Observation>) {
    for c in r.all("set-cookie").into_iter().take(30) {
        let name = c.split('=').next().unwrap_or("").trim();
        let lower = c.to_ascii_lowercase();
        let attrs: Vec<&str> = lower.split(';').skip(1).map(str::trim).collect();
        let has = |a: &str| {
            attrs
                .iter()
                .any(|x| x == &a || x.starts_with(&format!("{a}=")))
        };
        let mut missing = Vec::new();
        if https && !has("secure") {
            missing.push("Secure");
        }
        if !has("httponly") {
            missing.push("HttpOnly");
        }
        if !has("samesite") {
            missing.push("SameSite");
        }
        if attrs.iter().any(|a| a == &"samesite=none") && !has("secure") {
            out.push(obs(
                Sev::Warn,
                "Set-Cookie",
                format!("Cookie {name}: SameSite=None without Secure"),
                "Browsers reject this cookie.",
            ));
        } else if missing.is_empty() {
            out.push(obs(
                Sev::Pass,
                "Set-Cookie",
                format!("Cookie {name}: Secure, HttpOnly, SameSite"),
                "",
            ));
        } else {
            out.push(obs(Sev::Info, "Set-Cookie", format!("Cookie {name} without {}", missing.join(", ")), "HttpOnly is expected for session cookies; scripts that need the cookie cannot use it."));
        }
    }
}

fn cors(r: &Response, out: &mut Vec<Observation>) {
    let Some(origin) = r.header("access-control-allow-origin") else {
        return;
    };
    let creds = r
        .header("access-control-allow-credentials")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
    if origin.trim() == "*" && creds {
        out.push(obs(
            Sev::Warn,
            "Access-Control-Allow-Origin",
            "CORS * with credentials",
            "Browsers refuse this combination; the server likely means to echo specific origins.",
        ));
    } else if origin.trim() == "*" {
        out.push(obs(
            Sev::Info,
            "Access-Control-Allow-Origin",
            "CORS open to any origin",
            "Fine for public data; not for responses that depend on who is logged in.",
        ));
    } else {
        out.push(obs(
            Sev::Info,
            "Access-Control-Allow-Origin",
            format!(
                "CORS allows {origin}{}",
                if creds { " with credentials" } else { "" }
            ),
            "Check that this is not simply echoing the request's Origin.",
        ));
    }
}

/// Observations for a final response. `https` is the scheme it came over.
pub fn observe(r: &Response, https: bool) -> Vec<Observation> {
    let mut out = Vec::new();
    hsts(r, https, &mut out);
    csp(r, &mut out);
    framing(r, &mut out);
    simple(r, &mut out);
    cookies(r, https, &mut out);
    cors(r, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(headers: &[(&str, &str)]) -> Response {
        Response {
            status: 200,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    fn titles(o: &[Observation]) -> Vec<String> {
        o.iter().map(|x| x.title.clone()).collect()
    }

    #[test]
    fn hsts_cases() {
        let t = titles(&observe(&resp(&[]), true));
        assert!(t.contains(&"No HSTS".to_string()));
        let o = observe(
            &resp(&[(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload",
            )]),
            true,
        );
        assert_eq!(o[0].severity, Sev::Pass);
        assert!(o[0].title.contains("365 days, includeSubDomains, preload"));
        let o = observe(&resp(&[("strict-transport-security", "max-age=0")]), true);
        assert_eq!(o[0].severity, Sev::Warn);
        let o = observe(
            &resp(&[("Strict-Transport-Security", "max-age=600")]),
            false,
        );
        assert!(o[0].title.contains("plain HTTP"));
        assert!(!titles(&observe(&resp(&[]), false)).contains(&"No HSTS".to_string()));
    }

    #[test]
    fn html_page_checks() {
        let o = observe(&resp(&[("Content-Type", "text/html")]), true);
        let t = titles(&o);
        assert!(t.contains(&"No CSP on an HTML page".to_string()));
        assert!(t.contains(&"Page can be framed by any site".to_string()));
        let o = observe(
            &resp(&[
                ("Content-Type", "text/html"),
                (
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
                ),
            ]),
            true,
        );
        let t = titles(&o);
        assert!(t.contains(&"CSP allows 'unsafe-inline'".to_string()));
        assert!(t.contains(&"Framing limited by frame-ancestors".to_string()));
        // JSON responses are not nagged about framing or CSP.
        let t = titles(&observe(
            &resp(&[("Content-Type", "application/json")]),
            true,
        ));
        assert!(!t.iter().any(|x| x.contains("framed") || x.contains("CSP")));
    }

    #[test]
    fn cookies_cors_versions() {
        let o = observe(
            &resp(&[
                (
                    "Set-Cookie",
                    "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
                ),
                ("Set-Cookie", "pref=1; Path=/"),
                ("Set-Cookie", "x=1; SameSite=None"),
            ]),
            true,
        );
        let t = titles(&o);
        assert!(t.contains(&"Cookie sid: Secure, HttpOnly, SameSite".to_string()));
        assert!(t.contains(&"Cookie pref without Secure, HttpOnly, SameSite".to_string()));
        assert!(t.contains(&"Cookie x: SameSite=None without Secure".to_string()));
        let o = observe(
            &resp(&[
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ]),
            true,
        );
        assert!(titles(&o).contains(&"CORS * with credentials".to_string()));
        let o = observe(
            &resp(&[
                ("Server", "nginx/1.18.0"),
                ("X-Content-Type-Options", "nosniff"),
            ]),
            true,
        );
        let t = titles(&o);
        assert!(t.contains(&"Version disclosed: nginx/1.18.0".to_string()));
        assert!(t.contains(&"nosniff set".to_string()));
        assert!(
            !titles(&observe(&resp(&[("Server", "cloudflare")]), true))
                .iter()
                .any(|x| x.contains("Version"))
        );
    }
}

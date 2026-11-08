//! Redirects of HTTP-based carriers (HTTP, WebSocket): a carrier follows a
//! redirect only to its own host, never to another host and never from
//! `https` to `http` (`wss` to `ws`), so that no credential, pairing token,
//! join frame or prefix reaches another origin. The URLs are strings of
//! the form `scheme://authority/path?query`, the schemes `http`, `https`,
//! `ws` and `wss`.

use std::fmt;
use std::io;

/// The redirects a carrier request follows unless its adapter's options
/// set another bound.
pub const DEFAULT_MAX_REDIRECTS: usize = 5;

/// A redirect that a carrier did not follow: to another host or port,
/// from a secure scheme to an insecure one, one that would change a
/// `POST` into a `GET`, with credentials in the location, past the bound,
/// or without a valid `Location`. A dial fails with an [`io::Error`] of
/// kind [`io::ErrorKind::ConnectionRefused`] that carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectError {
    /// The redirect's status.
    pub status: u16,
    /// Its `Location` field, as it came (empty when it had none).
    pub location: String,
    /// Why it was not followed.
    pub reason: &'static str,
}

impl fmt::Display for RedirectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "redirect {} to {:?} refused: {}",
            self.status, self.location, self.reason
        )
    }
}

impl std::error::Error for RedirectError {}

impl From<RedirectError> for io::Error {
    fn from(e: RedirectError) -> Self {
        io::Error::new(io::ErrorKind::ConnectionRefused, e)
    }
}

/// Whether `status` is a redirect a carrier considers (301, 302, 303, 307,
/// 308).
pub fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// A URL taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Url<'a> {
    scheme: &'a str,
    authority: &'a str,
    /// The host, without brackets around an IPv6 address.
    host: &'a str,
    port: Option<u16>,
    /// The path and query, `/` at least.
    path: String,
}

/// `Some(true)` for `https`/`wss`, `Some(false)` for `http`/`ws`.
fn secure(scheme: &str) -> Option<bool> {
    match scheme.to_ascii_lowercase().as_str() {
        "https" | "wss" => Some(true),
        "http" | "ws" => Some(false),
        _ => None,
    }
}

/// The host and port of an authority, `None` when it is malformed or has
/// credentials.
fn host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if authority.contains('@') || authority.is_empty() {
        return None;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host, rest.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, Some(p)),
            Some(_) => return None,
            None => (authority, None),
        }
    };
    let port = match port {
        Some(p) => Some(p.parse().ok()?),
        None => None,
    };
    (!host.is_empty()).then_some((host, port))
}

/// An authority and the path and query after it, the fragment dropped.
fn split_authority(rest: &str) -> (&str, &str) {
    let rest = rest.split('#').next().unwrap_or_default();
    match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    }
}

fn parse(url: &str) -> Option<Url<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    secure(scheme)?;
    let (authority, path) = split_authority(rest);
    let (host, port) = host_port(authority)?;
    Some(Url {
        scheme,
        authority,
        host,
        port,
        path: normalize(path),
    })
}

fn normalize(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_owned()
    }
}

impl Url<'_> {
    fn secure(&self) -> bool {
        secure(self.scheme).unwrap_or(false)
    }

    fn effective_port(&self) -> u16 {
        self.port.unwrap_or(if self.secure() { 443 } else { 80 })
    }
}

/// Whether `a` and `b` are URLs of one origin: the same scheme (`ws` and
/// `http` as one, `wss` and `https` as one), host and port.
pub fn same_origin(a: &str, b: &str) -> bool {
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => {
            a.secure() == b.secure()
                && a.host.eq_ignore_ascii_case(b.host)
                && a.effective_port() == b.effective_port()
        }
        _ => false,
    }
}

/// The URL a carrier request with `method` to `from`, answered with the
/// redirect `status` and `location`, is repeated at, with the same method,
/// header fields and body: `location` resolved against `from`, without a
/// fragment, in the scheme family of `from` (`ws`/`wss` or
/// `http`/`https`). Refused: another host name, a secure scheme to an
/// insecure one, another port without a scheme upgrade, credentials in the
/// location, and a 301, 302 or 303 of a request other than `GET` or
/// `HEAD` unless it is a pure scheme upgrade (the same host, path and
/// query over the secure scheme). `status` must satisfy [`is_redirect`].
pub fn check(
    from: &str,
    method: &str,
    status: u16,
    location: Option<&str>,
) -> Result<String, RedirectError> {
    let refuse = |reason| RedirectError {
        status,
        location: location.unwrap_or_default().to_owned(),
        reason,
    };
    let location = location
        .filter(|l| !l.is_empty())
        .ok_or_else(|| refuse("no Location"))?;
    let from = parse(from).ok_or_else(|| refuse("invalid URL"))?;
    let (to_secure, authority, path) = if let Some((scheme, rest)) = location
        .split_once("://")
        .filter(|(s, _)| !s.contains(['/', '?', '#']))
    {
        let to_secure = secure(scheme).ok_or_else(|| refuse("unknown scheme"))?;
        let (authority, path) = split_authority(rest);
        (to_secure, authority, normalize(path))
    } else if let Some(rest) = location.strip_prefix("//") {
        let (authority, path) = split_authority(rest);
        (from.secure(), authority, normalize(path))
    } else {
        let reference = location.split('#').next().unwrap_or_default();
        (
            from.secure(),
            from.authority,
            resolve_path(&from.path, reference),
        )
    };
    if authority.contains('@') {
        return Err(refuse("credentials in the Location"));
    }
    let (host, port) = host_port(authority).ok_or_else(|| refuse("invalid Location"))?;
    if !host.eq_ignore_ascii_case(from.host) {
        return Err(refuse("another host"));
    }
    let from_secure = from.secure();
    if from_secure && !to_secure {
        return Err(refuse("downgrade to an insecure scheme"));
    }
    let to_port = port.unwrap_or(if to_secure { 443 } else { 80 });
    if from_secure == to_secure && to_port != from.effective_port() {
        return Err(refuse("another port"));
    }
    if path.contains([' ', '\r', '\n']) {
        return Err(refuse("invalid Location"));
    }
    let upgrade = !from_secure && to_secure;
    let ws = from.scheme.eq_ignore_ascii_case("ws") || from.scheme.eq_ignore_ascii_case("wss");
    let scheme = match (ws, to_secure) {
        (true, true) => "wss",
        (true, false) => "ws",
        (false, true) => "https",
        (false, false) => "http",
    };
    let get = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");
    if !get && status != 307 && status != 308 && !(upgrade && path == from.path) {
        // A 301, 302 or 303 turns a POST into a GET; only a pure scheme
        // upgrade is taken as meant for the same request.
        return Err(refuse("would change the method to GET"));
    }
    Ok(format!("{scheme}://{authority}{path}"))
}

/// A relative reference against the base path (RFC 3986 Section 5.2),
/// its dot segments removed.
fn resolve_path(base: &str, reference: &str) -> String {
    let base_path = base.split('?').next().unwrap_or("/");
    let merged = if reference.starts_with('/') {
        reference.to_owned()
    } else if reference.is_empty() {
        return base.to_owned();
    } else if let Some(query) = reference.strip_prefix('?') {
        format!("{base_path}?{query}")
    } else {
        let dir = &base_path[..base_path.rfind('/').map_or(0, |i| i + 1)];
        let dir = if dir.is_empty() { "/" } else { dir };
        format!("{dir}{reference}")
    };
    let (path, query) = match merged.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (merged.as_str(), None),
    };
    let mut out: Vec<&str> = Vec::new();
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    for (i, s) in segments.iter().enumerate() {
        let last = i + 1 == segments.len();
        match *s {
            "." => {
                if last {
                    out.push("");
                }
            }
            ".." => {
                out.pop();
                if last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    let mut path = format!("/{}", out.join("/"));
    if let Some(q) = query {
        path.push('?');
        path.push_str(q);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to(from: &str, location: &str) -> Result<String, &'static str> {
        check(from, "GET", 302, Some(location)).map_err(|e| e.reason)
    }

    #[test]
    fn same_host_redirects_resolve() {
        assert_eq!(to("ws://a.example/x/y", "/z").unwrap(), "ws://a.example/z");
        assert_eq!(
            to("ws://a.example/x/y", "z?q=1").unwrap(),
            "ws://a.example/x/z?q=1"
        );
        assert_eq!(
            to("ws://a.example/x/y", "../z#f").unwrap(),
            "ws://a.example/z"
        );
        assert_eq!(
            to("ws://a.example:8080/x", "http://A.example:8080/n").unwrap(),
            "ws://A.example:8080/n"
        );
        assert_eq!(
            to("wss://a.example/x", "//a.example/n").unwrap(),
            "wss://a.example/n"
        );
        assert_eq!(
            to("http://[::1]:8080/x", "/y").unwrap(),
            "http://[::1]:8080/y"
        );
    }

    #[test]
    fn a_scheme_upgrade_may_change_the_port() {
        assert_eq!(
            to("ws://a.example/x", "https://a.example/x").unwrap(),
            "wss://a.example/x"
        );
        assert_eq!(
            to("http://a.example:8080/x", "https://a.example:8443/x").unwrap(),
            "https://a.example:8443/x"
        );
    }

    #[test]
    fn refusals() {
        assert_eq!(
            to("ws://a.example/x", "ws://b.example/x"),
            Err("another host")
        );
        assert_eq!(
            to("https://a.example/x", "http://a.example/x"),
            Err("downgrade to an insecure scheme")
        );
        assert_eq!(
            to("ws://a.example/x", "ws://a.example:81/x"),
            Err("another port")
        );
        assert_eq!(
            to("ws://a.example/x", "ws://u:p@a.example/x"),
            Err("credentials in the Location")
        );
        assert_eq!(
            to("ws://a.example/x", "ftp://a.example/x"),
            Err("unknown scheme")
        );
        assert_eq!(
            check("ws://a/", "GET", 301, None).unwrap_err().reason,
            "no Location"
        );
    }

    #[test]
    fn a_post_keeps_its_method_only_where_the_status_says() {
        let post = |status, loc| check("http://a/x", "POST", status, Some(loc));
        assert_eq!(post(307, "/y").unwrap(), "http://a/y");
        assert_eq!(post(308, "/y").unwrap(), "http://a/y");
        assert_eq!(
            post(302, "/y").unwrap_err().reason,
            "would change the method to GET"
        );
        assert_eq!(post(301, "https://a/x").unwrap(), "https://a/x");
    }

    #[test]
    fn origins() {
        assert!(same_origin("http://a/x", "ws://A:80/y"));
        assert!(!same_origin("http://a/x", "https://a/x"));
        assert!(!same_origin("http://a:81/x", "http://a/x"));
    }
}

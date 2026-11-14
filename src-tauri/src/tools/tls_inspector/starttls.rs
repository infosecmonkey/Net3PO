//! STARTTLS upgrades for SMTP, IMAP, POP3 and FTP: the plain-text exchange
//! that comes before the TLS handshake. Every line read is bounded, and the
//! whole exchange is recorded so the UI can show what the server said.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

/// Longest server line accepted.
const MAX_LINE: usize = 8 * 1024;
/// Most bytes read before TLS starts.
const MAX_TOTAL: usize = 64 * 1024;
/// Most lines in one multi-line reply.
const MAX_REPLY_LINES: usize = 200;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StartTls {
    None,
    Smtp,
    Imap,
    Pop3,
    Ftp,
}

impl StartTls {
    pub fn default_port(self) -> u16 {
        match self {
            Self::None => 443,
            Self::Smtp => 587,
            Self::Imap => 143,
            Self::Pop3 => 110,
            Self::Ftp => 21,
        }
    }
}

/// Plain-text lines exchanged before TLS, prefixed `S:` (server) or `C:`.
pub type Transcript = Vec<String>;

struct Lines<'a, S: Read + Write> {
    s: &'a mut S,
    buf: Vec<u8>,
    total: usize,
    log: &'a mut Transcript,
}

impl<S: Read + Write> Lines<'_, S> {
    /// One CRLF- or LF-terminated line. Reads a byte at a time so no TLS
    /// bytes are consumed after the final reply.
    fn line(&mut self) -> Result<String, String> {
        self.buf.clear();
        let mut b = [0u8; 1];
        loop {
            match self.s.read(&mut b) {
                Ok(0) => return Err("the server closed the connection".into()),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err("timed out waiting for the server".into());
                }
                Err(e) => return Err(e.to_string()),
            }
            self.total += 1;
            if self.total > MAX_TOTAL {
                return Err("the server sent too much before TLS".into());
            }
            if b[0] == b'\n' {
                break;
            }
            if self.buf.len() >= MAX_LINE {
                return Err("server line too long".into());
            }
            self.buf.push(b[0]);
        }
        if self.buf.last() == Some(&b'\r') {
            self.buf.pop();
        }
        let line = String::from_utf8_lossy(&self.buf).into_owned();
        self.log.push(format!("S: {line}"));
        Ok(line)
    }

    fn send(&mut self, cmd: &str) -> Result<(), String> {
        self.log.push(format!("C: {cmd}"));
        self.s
            .write_all(format!("{cmd}\r\n").as_bytes())
            .and_then(|_| self.s.flush())
            .map_err(|e| e.to_string())
    }

    /// A numeric reply (SMTP, FTP): `250-...` continues, `250 ...` ends.
    fn reply(&mut self) -> Result<(u16, Vec<String>), String> {
        let mut lines = Vec::new();
        loop {
            let l = self.line()?;
            let code: u16 = l
                .get(..3)
                .and_then(|c| c.parse().ok())
                .ok_or_else(|| format!("unexpected reply: {l}"))?;
            let more = l.as_bytes().get(3) == Some(&b'-');
            lines.push(l.get(4..).unwrap_or("").to_string());
            if !more {
                return Ok((code, lines));
            }
            if lines.len() >= MAX_REPLY_LINES {
                return Err("reply has too many lines".into());
            }
        }
    }
}

fn expect(code: u16, want: u16, what: &str) -> Result<(), String> {
    if code == want {
        Ok(())
    } else {
        Err(format!("{what}: server answered {code}"))
    }
}

/// Run the protocol's upgrade on `s`. On success the next bytes are TLS.
pub fn upgrade<S: Read + Write>(
    s: &mut S,
    mode: StartTls,
    log: &mut Transcript,
) -> Result<(), String> {
    let mut l = Lines {
        s,
        buf: Vec::with_capacity(256),
        total: 0,
        log,
    };
    match mode {
        StartTls::None => Ok(()),
        StartTls::Smtp => {
            let (code, _) = l.reply()?;
            expect(code, 220, "greeting")?;
            l.send("EHLO net3po.invalid")?;
            let (code, caps) = l.reply()?;
            expect(code, 250, "EHLO")?;
            if !caps
                .iter()
                .any(|c| c.trim().eq_ignore_ascii_case("STARTTLS"))
            {
                return Err("the server does not offer STARTTLS".into());
            }
            l.send("STARTTLS")?;
            let (code, _) = l.reply()?;
            expect(code, 220, "STARTTLS")
        }
        StartTls::Ftp => {
            let (code, _) = l.reply()?;
            expect(code, 220, "greeting")?;
            l.send("AUTH TLS")?;
            let (code, _) = l.reply()?;
            expect(code, 234, "AUTH TLS")
        }
        StartTls::Pop3 => {
            let g = l.line()?;
            if !g.starts_with("+OK") {
                return Err(format!("unexpected greeting: {g}"));
            }
            l.send("STLS")?;
            let r = l.line()?;
            if r.starts_with("+OK") {
                Ok(())
            } else {
                Err(format!("STLS refused: {r}"))
            }
        }
        StartTls::Imap => {
            let g = l.line()?;
            if !g.starts_with("* OK") {
                return Err(format!("unexpected greeting: {g}"));
            }
            l.send("a1 STARTTLS")?;
            for _ in 0..MAX_REPLY_LINES {
                let r = l.line()?;
                if let Some(rest) = r.strip_prefix("a1 ") {
                    return if rest.starts_with("OK") {
                        Ok(())
                    } else {
                        Err(format!("STARTTLS refused: {rest}"))
                    };
                }
            }
            Err("no tagged reply to STARTTLS".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Scripted server: reads come from `input`, writes are collected.
    struct Fake {
        input: Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl Fake {
        fn new(s: &str) -> Self {
            Self {
                input: Cursor::new(s.as_bytes().to_vec()),
                sent: Vec::new(),
            }
        }
    }

    impl Read for Fake {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }

    impl Write for Fake {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn run(mode: StartTls, server: &str) -> (Result<(), String>, String, Transcript) {
        let mut f = Fake::new(server);
        let mut log = Vec::new();
        let r = upgrade(&mut f, mode, &mut log);
        (r, String::from_utf8(f.sent).unwrap(), log)
    }

    #[test]
    fn smtp() {
        let (r, sent, log) = run(
            StartTls::Smtp,
            "220 mx.example.com ESMTP\r\n250-mx.example.com\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 8BITMIME\r\n220 2.0.0 Ready\r\nTLSBYTES",
        );
        assert_eq!(r, Ok(()));
        assert_eq!(sent, "EHLO net3po.invalid\r\nSTARTTLS\r\n");
        assert_eq!(log.first().unwrap(), "S: 220 mx.example.com ESMTP");
        let (r, _, _) = run(StartTls::Smtp, "220 hi\r\n250-mx\r\n250 SIZE 1000\r\n");
        assert!(r.unwrap_err().contains("does not offer"));
        let (r, _, _) = run(StartTls::Smtp, "554 go away\r\n");
        assert!(r.unwrap_err().contains("554"));
    }

    #[test]
    fn imap_pop3_ftp() {
        let (r, sent, _) = run(
            StartTls::Imap,
            "* OK ready\r\n* note\r\na1 OK Begin TLS\r\n",
        );
        assert_eq!(r, Ok(()));
        assert_eq!(sent, "a1 STARTTLS\r\n");
        let (r, _, _) = run(StartTls::Imap, "* OK ready\r\na1 BAD no\r\n");
        assert!(r.is_err());
        let (r, sent, _) = run(StartTls::Pop3, "+OK POP3\r\n+OK go\r\n");
        assert_eq!((r, sent.as_str()), (Ok(()), "STLS\r\n"));
        let (r, sent, _) = run(
            StartTls::Ftp,
            "220-Welcome\r\n220 FTP\r\n234 AUTH TLS ok\r\n",
        );
        assert_eq!((r, sent.as_str()), (Ok(()), "AUTH TLS\r\n"));
    }

    #[test]
    fn hostile_servers() {
        let long = format!("220 {}\r\n", "a".repeat(MAX_LINE + 10));
        assert!(
            run(StartTls::Smtp, &long)
                .0
                .unwrap_err()
                .contains("too long")
        );
        let flood = "220-x\r\n".repeat(MAX_REPLY_LINES + 5);
        assert!(run(StartTls::Smtp, &flood).0.is_err());
        assert!(run(StartTls::Smtp, "").0.unwrap_err().contains("closed"));
        assert!(
            run(StartTls::Smtp, "hello\r\n")
                .0
                .unwrap_err()
                .contains("unexpected")
        );
        let big = "* x\r\n".repeat(20_000);
        assert!(run(StartTls::Imap, &format!("* OK\r\n{big}")).0.is_err());
    }
}

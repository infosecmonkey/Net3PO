//! Obfuscator: replace IPs, hostnames, accounts, secrets, MACs and serial
//! numbers in pasted text before it goes to an AI assistant, a ticket or an
//! email, then map a reply back. Built on the report redaction engine.

pub mod commands;
pub mod core;

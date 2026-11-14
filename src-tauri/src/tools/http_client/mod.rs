//! HTTP/API troubleshooter: send a request with any method, headers and
//! body; follow redirects hop by hop with DNS, connect, TLS and first-byte
//! timings; test a hostname against a chosen IP; explain response headers.

pub mod client;
pub mod commands;
pub mod observe;
pub mod redirect;
pub mod url;
pub mod wire;

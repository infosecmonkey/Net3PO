//! Script decoder: statically unwrap obfuscated Python, Bash, PowerShell and
//! JavaScript layer by layer, extract IOCs and flag suspicious behavior. Input
//! is parsed, never executed.

pub mod bash;
pub mod codecs;
pub mod commands;
pub mod core;
pub mod eval;
pub mod flags;
pub mod ioc;
pub mod lexer;
pub mod powershell;

//! Script decoder: statically unwrap obfuscated scripts layer by layer, extract
//! IOCs and flag suspicious behavior. Input is parsed, never executed.

pub mod codecs;
pub mod commands;
pub mod core;
pub mod eval;
pub mod flags;
pub mod ioc;
pub mod lexer;

//! Shell explainer: break a POSIX shell or Bash command line into its parts
//! and describe each one, from a built-in command list and local man pages.
//! Input is parsed, never run.

pub mod commands;
pub mod core;
pub mod db;
pub mod lexer;
pub mod man;

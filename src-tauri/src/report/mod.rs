//! Report export shared by every tool: a format-independent report model and
//! renderers for HTML, Markdown, plain text and PDF. Tools build the model
//! from their results; nothing here knows about a specific tool.

pub mod commands;
pub mod core;
mod html;
mod markdown;
mod pdf;
mod text;

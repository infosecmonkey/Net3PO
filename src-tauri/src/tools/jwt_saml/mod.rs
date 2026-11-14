//! JWT and SAML inspector: decode tokens and SAML messages, verify JWT
//! signatures only with keys the user supplies, and check times, issuer,
//! audience and recipient against expectations. Offline.

pub mod commands;
pub mod jwt;
pub mod saml;

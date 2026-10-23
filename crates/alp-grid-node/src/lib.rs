//! The Grid node: guardian and publisher logic ([`engine`]), the local HTTP API ([`api`]),
//! configuration, identity, and the observer that feeds the public Console.

pub mod api;
pub mod config;
pub mod engine;
pub mod observer;

pub use engine::{Engine, Identity, PublishReport, SearchQuery, SearchResult};

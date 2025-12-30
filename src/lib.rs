//! Crusher - Time series generator from raw events ingested via Giganto server.
//!
//! This crate provides functionality for generating time series statistics from
//! raw events ingested through a Giganto server. It handles the subscription
//! pipeline, time series generation, and policy management.

pub mod client;
pub mod subscribe;

//! The configuration definitions of honeypot-rs

use serde::{Deserialize, Serialize};

/// The settings for the honeypot
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct HoneypotConfig {
    /// The device to capture packets on
    pub device: String,
}

/// The main configuration file of honeypot-rs
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    /// The config for the honeypot
    pub honeypot: HoneypotConfig,
}

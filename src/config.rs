//! The configuration definitions of honeypot-rs

use std::fs;
use std::path::Path;

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

/// Retrieve the [Config] by a path
///
/// If the file does not exist or could not be parsed, an error is returned
pub fn get_config(path: &str) -> Result<Config, String> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(format!("Config file {path} does not exist"));
    }

    if !p.is_file() {
        return Err(format!("Config file {path} is no file"));
    }

    let config_str =
        fs::read_to_string(p).map_err(|e| format!("Error reading from config file: {e}"))?;

    let config =
        toml::from_str(&config_str).map_err(|e| format!("Error parsing config file: {e}"))?;

    Ok(config)
}

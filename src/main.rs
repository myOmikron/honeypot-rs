//! # honeypot-rs

#![warn(missing_docs)]

use std::env;
use std::sync::mpsc;

use clap::Parser;
use log::debug;
use pcap::Device;

use crate::capture::{
    start_icmp_capture, start_icmp_v6_capture, start_tcp_capture, start_udp_capture,
};
use crate::config::get_config;

pub mod capture;
pub mod config;
pub mod packets;

/// A honeypot written in rust
#[derive(Parser)]
#[clap(version, author = "myOmikron")]
pub struct Cli {
    /// path to retrieve the config file for honeypot-rs from
    #[clap(long)]
    #[clap(default_value_t = String::from("/etc/honeypot-rs/config.toml"))]
    config_path: String,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "debug")
    }

    env_logger::init();

    let cli = Cli::parse();
    let config = get_config(&cli.config_path)?;

    let addresses = Device::list()
        .map_err(|e| format!("Error obtaining devices: {e}"))?
        .into_iter()
        .find(|d| d.name == config.honeypot.device)
        .ok_or(format!(
            "Couldn't find device with name {}",
            &config.honeypot.device
        ))?
        .addresses;

    let (tx, rx) = mpsc::channel();

    let _tcp_handle = start_tcp_capture(&addresses, &config.honeypot.device, tx.clone())?;
    let _udp_handle = start_udp_capture(&addresses, &config.honeypot.device, tx.clone())?;
    let _icmp_handle = start_icmp_capture(&addresses, &config.honeypot.device, tx.clone())?;
    let _icmp_handle = start_icmp_v6_capture(&addresses, &config.honeypot.device, tx)?;

    while let Ok(packet) = rx.recv() {
        debug!("Received packet: {packet}");
    }

    Ok(())
}

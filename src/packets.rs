//! The definitions of the packets live here

use std::fmt::{Display, Formatter};
use std::net::IpAddr;

/// Representation of an incoming packet
#[derive(Copy, Clone, Debug)]
pub enum Packet {
    /// an tcp packet
    Tcp {
        /// The source address of the packet
        source_address: IpAddr,
        /// The source port of the packet
        source_port: u16,
        /// The destination address of the packet
        destination_address: IpAddr,
        /// The destination port of the packet
        destination_port: u16,
    },
    /// an udp packet
    Udp {
        /// The source address of the packet
        source_address: IpAddr,
        /// The source port of the packet
        source_port: u16,
        /// The destination address of the packet
        destination_address: IpAddr,
        /// The destination port of the packet
        destination_port: u16,
    },
}

impl Display for Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Packet::Tcp {
                source_address,
                source_port,
                destination_address,
                destination_port,
            } => {
                write!(
                    f,
                    "tcp {{{source_address}:{source_port} -> {destination_address}:{destination_port}}}",
                )
            }
            Packet::Udp {
                source_address,
                source_port,
                destination_address,
                destination_port,
            } => {
                write!(
                    f,
                    "udp {{{source_address}:{source_port} -> {destination_address}:{destination_port}}}",
                )
            }
        }
    }
}

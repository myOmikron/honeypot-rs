//! The definitions of the packets live here

use std::fmt::{Display, Formatter};
use std::net::IpAddr;

/// Possible packet types
#[derive(Copy, Clone, Debug)]
pub enum PacketType {
    /// an tcp packet
    Tcp,
    /// an udp packet
    Udp,
}

/// Representation of an incoming packet
#[derive(Copy, Clone, Debug)]
pub struct Packet {
    /// The source of the packet
    pub source: (IpAddr, u16),
    /// The destination of the packet
    pub destination: (IpAddr, u16),
    /// The type of the packet
    pub packet_type: PacketType,
}

impl Display for Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {{{}:{} -> {}:{}}}",
            match self.packet_type {
                PacketType::Udp => "udp",
                PacketType::Tcp => "tcp",
            },
            self.source.0,
            self.source.1,
            self.destination.0,
            self.destination.1
        )
    }
}

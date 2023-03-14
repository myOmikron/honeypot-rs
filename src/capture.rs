//! This module holds everything regarding the capturing of packets

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::Sender;
use std::thread;
use std::thread::JoinHandle;

use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use log::{debug, error, info};
use pcap::{Active, Capture};

use crate::packets::Packet;

/// Open a device for capturing
///
/// `capture_device`: [&str]: The device to capture from
pub fn open_device(capture_device: &str) -> Result<Capture<Active>, String> {
    Capture::from_device(capture_device)
        .map_err(|e| format!("Could not retrieve device {capture_device}: {e}"))?
        .timeout(100)
        .open()
        .map_err(|e| format!("Could not open device {capture_device}: {e}"))
}

/// Retrieve a [Packet] from [PacketHeaders].
///
/// This assumes that the packet is either a tcp or an udp packet
pub fn get_packet_from_headers(headers: PacketHeaders) -> Packet {
    let Some(ip_header) = headers.ip else {
        unreachable!("tcp or udp filter applied");
    };

    let (source_address, destination_address) = match ip_header {
        IpHeader::Version4(h, _) => (
            IpAddr::V4(Ipv4Addr::from(h.source)),
            IpAddr::V4(Ipv4Addr::from(h.destination)),
        ),
        IpHeader::Version6(h, _) => (
            IpAddr::V6(Ipv6Addr::from(h.source)),
            IpAddr::V6(Ipv6Addr::from(h.destination)),
        ),
    };

    match headers.transport {
        Some(TransportHeader::Tcp(tcp)) => Packet::Tcp {
            source_address,
            source_port: tcp.source_port,
            destination_address,
            destination_port: tcp.destination_port,
        },
        Some(TransportHeader::Udp(udp)) => Packet::Udp {
            source_address,
            source_port: udp.source_port,
            destination_address,
            destination_port: udp.destination_port,
        },
        _ => unreachable!("Invalid packet"),
    }
}

/// Start capture of tcp packets.
///
/// Any captured packets will be parsed in [Packet] and send via provided channel.
///
/// `hostname`: [&str]: The hostname of the executing system. This will be used to check if packets
/// are incoming or outgoing.
/// `capture_device`: [&str]: The name of the device that should be used for capturing.
/// `tx`: [Sender] of [Packet]. The received packets will be sent via this sender.
pub fn start_tcp_capture(
    hostname: &str,
    capture_device: &str,
    tx: Sender<Packet>,
) -> Result<JoinHandle<()>, String> {
    let mut cap = open_device(capture_device)?;

    info!("Opened device {capture_device} for tcp capturing");

    let filter = format!("! src host {hostname} && dst host {hostname} && tcp");
    cap.filter(&filter, true)
        .map_err(|_| "Could not apply tcp filter")?;

    debug!("Applied filter: {filter}");

    let tcp_handle = thread::spawn(move || {
        while let Ok(packet) = cap.next_packet() {
            let p = match PacketHeaders::from_ethernet_slice(packet.data) {
                Ok(v) => get_packet_from_headers(v),
                Err(err) => {
                    error!("Error deserializing tcp packet: {err}");
                    continue;
                }
            };

            if let Err(err) = tx.send(p) {
                error!("Error sending to tx: {err}");
            }
        }
    });

    Ok(tcp_handle)
}

/// Start capturing udp packets from the given capture device
///
/// Any captured packets will be parsed in [Packet] and send via provided channel.
///
/// `hostname`: [&str]: The hostname of the executing system. This will be used to check if packets
/// are incoming or outgoing.
/// `capture_device`: [&str]: The name of the device that should be used for capturing.
/// `tx`: [Sender] of [Packet]. The received packets will be sent via this sender.
pub fn start_udp_capture(
    hostname: &str,
    capture_device: &str,
    tx: Sender<Packet>,
) -> Result<JoinHandle<()>, String> {
    let mut cap = open_device(capture_device)?;

    info!("Opened device {capture_device} for udp capturing");

    let filter = format!("! src host {hostname} && dst host {hostname} && udp");
    cap.filter(&filter, true)
        .map_err(|_| "Could not apply udp filter")?;

    debug!("Applied filter: {filter}");

    Ok(thread::spawn(move || {
        while let Ok(packet) = cap.next_packet() {
            let p = match PacketHeaders::from_ethernet_slice(packet.data) {
                Ok(h) => get_packet_from_headers(h),
                Err(err) => {
                    error!("Error deserializing udp packet: {err}");
                    continue;
                }
            };

            if let Err(err) = tx.send(p) {
                error!("Error sending packet to tx: {err}");
            }
        }
    }))
}

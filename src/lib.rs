use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use pnet::datalink;
use pnet::datalink::{Channel, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};
use pnet::packet::Packet;

pub type Mac = [u8; 6];

pub struct ArpClient {
    interface: NetworkInterface,
    txrx: (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>),
}

impl ArpClient {
    pub fn build_with_description(description: &str) -> io::Result<Self> {
        for interface in datalink::interfaces() {
            if interface.description == description {
                return match datalink::channel(&interface, Default::default())? {
                    Channel::Ethernet(tx, rx) => {
                        Ok(ArpClient { interface, txrx: (tx, rx) })
                    }
                    _ => Err(std::io::Error::new(io::ErrorKind::Other, "invalid channel"))
                };
            }
        };
        Err(io::Error::new(io::ErrorKind::Other, "invalid description"))
    }

    pub fn build_with_name(name: &str) -> std::io::Result<Self> {
        for interface in datalink::interfaces() {
            if interface.name == name {
                return match datalink::channel(&interface, Default::default())? {
                    Channel::Ethernet(tx, rx) => {
                        Ok(ArpClient { interface, txrx: (tx, rx) })
                    }
                    _ => Err(io::Error::new(io::ErrorKind::Other, "invalid channel"))
                };
            }
        }
        Err(io::Error::new(io::ErrorKind::Other, "invalid name"))
    }

    pub fn get_mac(&mut self, target_ip: Ipv4Addr) -> Result<Mac, Box<dyn Error>> {
        let (tx, rx) = &mut self.txrx;
        let source_mac = self.interface.mac.ok_or(io::Error::new(io::ErrorKind::Other, "no interface mac address"))?;
        let source_ip = self.interface.ips.iter()
            .find(|ip| ip.is_ipv4())
            .map(|ip| match ip.ip() {
                IpAddr::V4(ip) => ip,
                _ => unreachable!(),
            })
            .ok_or(io::Error::new(io::ErrorKind::Other, "no interface ip address"))?;

        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
            .ok_or(io::Error::new(io::ErrorKind::Other, "create ethernet packet error"))?;

        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)
            .ok_or(io::Error::new(io::ErrorKind::Other, "create arp packet error"))?;

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet());

        tx.send_to(ethernet_packet.packet(), None)
            .ok_or(io::Error::new(io::ErrorKind::Other, "send arp packet error"))??;

        let start_time = Instant::now();

        loop {
            if start_time.elapsed() > Duration::from_secs(3) {
                return Err(Box::new(io::Error::new(io::ErrorKind::TimedOut, "timeout")));
            }

            let packet = rx.next()?;
            let ethernet_packet = EthernetPacket::new(packet)
                .ok_or(io::Error::new(io::ErrorKind::Other, "decode ethernet packet error"))?;

            if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                let arp_packet = ArpPacket::new(ethernet_packet.payload())
                    .ok_or(io::Error::new(io::ErrorKind::Other, "decode arp packet error"))?;

                if arp_packet.get_operation() == ArpOperations::Reply &&
                    arp_packet.get_target_proto_addr() == source_ip &&
                    arp_packet.get_target_hw_addr() == source_mac &&
                    arp_packet.get_sender_proto_addr() == target_ip {
                    let target_mac: MacAddr = arp_packet.get_sender_hw_addr();
                    let mac: Mac = unsafe { std::mem::transmute(target_mac) };
                    return Ok(mac);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::ArpClient;

    #[test]
    fn it_works() {
        let mut client = ArpClient::build_with_description("Intel(R) Wireless-AC 9560 160MHz").unwrap();
        let mac = client.get_mac(Ipv4Addr::new(192, 168, 2, 105)).unwrap();
        let mut str = format!("{:x?}", mac);
        str.make_ascii_uppercase();
        println!("{}", str)
    }
}

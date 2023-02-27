extern crate pnet;

use pnet::datalink::interfaces;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::ipnetwork::IpNetwork;
use std::fmt::format;
use std::net::{self, IpAddr, Ipv4Addr, UdpSocket, TcpStream, SocketAddr};

use pnet::packet::MutablePacket;
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
use pnet_base::MacAddr;


fn forge_frame<'a>(
    buf_frame: &'a mut [u8],
    src: &MacAddr,
    dst: &MacAddr,
    payload: Vec<u8>,
) -> Result<MutableEthernetPacket<'a>, ()> {


    
    match MutableEthernetPacket::new(&mut buf_frame[..]){
        Some(mut frame) => {
            frame.set_source(*src);
            frame.set_destination(*dst);
            frame.set_ethertype(EtherTypes::Ipv4);
            frame.set_payload(&payload);
            Ok(frame)
        },
        _ => Err(())
    }
}

fn get_interface_by_name(name: String) -> Option<NetworkInterface> {
    interfaces().into_iter().filter(|x| x.name == name).next()
}

/// Get the interface from the local ip
fn get_interface_by_ip (local_addr: IpAddr) -> Option<NetworkInterface> {

    let local_ip = IpNetwork::from(local_addr).ip();
    println!("{:?}", local_ip);

    let fake_ip = IpNetwork::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).unwrap();

    let ip_match = |ip: &IpNetwork| {
        println!("{:?}", ip);
        ip.ip().eq(&local_ip)
    };

    interfaces().into_iter().filter(|x| local_ip == (x.ips.clone().into_iter().filter(ip_match).next().unwrap_or(fake_ip)).ip()).next()

  
    //interfaces().into_iter().find(|x| local_ip == x.ips.clone().into_iter().filter(|ip| ip.eq(&local_ip)).next().expect("Error getting an interface"))
}

fn get_source_ip(dst: IpAddr, port: u32) -> Option<SocketAddr>{

    let local_socket = UdpSocket::bind("0.0.0.0:0").expect("Error binding");
    let sd = format!("{}:{}", dst, port);
    match local_socket.connect(sd) {
        Ok(_) => 
            match local_socket.local_addr() {
                Ok(l_addr) => Some(l_addr),
                Err(_) => {
                    println!("Error binding");
                    None
                }
            },
        Err(_) => {
            println!("Error binding");
            None
        }
    }
}

fn get_iface_index() {
    
}

fn send_raw_arp()
{
   
    let mut arp_p = [0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0x28u8, 0xdfu8, 0xebu8, 0x2bu8, 0x7du8, 0x11u8, 0x08u8, 0x06u8, 0x00u8, 0x01,
                     0x08u8, 0x00u8, 0x06u8, 0x04u8, 0x00u8, 0x01u8, 0x28u8, 0xdfu8, 0xebu8, 0x2bu8, 0x7du8, 0x11u8, 0xc0u8, 0xa8u8, 0x00u8, 0x01,
                     0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xc0u8, 0xa8u8, 0x00u8, 0x01u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00,
                     0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00].to_vec();
    
    
    // Get the interface which will be used for sending the frame through.
    let current_target = Ipv4Addr::new(192, 168, 0, 1);
    let iface = match get_source_ip(IpAddr::V4(current_target), 50000u32) {
        Some(x) => {
            match get_interface_by_ip(x.ip()) {
                Some(iface) => iface,
                _ => return ()
            }
        },
        _ => return ()
    };
    
    match MutableEthernetPacket::new(&mut arp_p[..]) {
        Some(mut frame1) => {send_frame(frame1.packet_mut(), iface);},
        _ => ()
    }       

}

fn send_frame(frame: &mut [u8], iface: NetworkInterface )
{
  // "enx3ce1a14e5cbc"
    //let iface = get_interface_by_name("wlp0s20f3".to_string());
//    let interface = match iface.clone(){
//        Some(x) => x,
//        _ => panic!("An error occurred when getting iface")
//    };
        
    let (mut tx, _) = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    tx.send_to(frame, None);

}
// Invoke as echo <interface name>
fn main() {


    let src = MacAddr(0x28, 0xdf, 0xeb, 0x2b, 0x7d, 0x11);
    let dst = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let payload: Vec<u8> = "abcd".as_bytes().to_vec();

    // Get the interface which will be used for sending the frame through.
    let current_target = Ipv4Addr::new(192, 168, 0, 1);
    let iface = match get_source_ip(IpAddr::V4(current_target), 50000u32) {
        Some(x) => {
            match get_interface_by_ip(x.ip()) {
                Some(iface) => iface,
                _ => return ()
            }
        },
        _ => return ()
    };

    // forge the frame
    let mut buf_frame = [0u8; 20];
    let mut frame = match forge_frame (&mut buf_frame, &src, &dst, payload) {
        Ok(mut frame) => {
            println!("{:?}", frame.packet_mut());
            frame
        }
        Err(_) => return ()
    };

    // Send the frame
    send_frame(frame.packet_mut(), iface);
    
    send_raw_arp();
}


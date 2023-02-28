use std::net::{IpAddr, Ipv4Addr, UdpSocket, SocketAddr, ToSocketAddrs};
use pnet_base::MacAddr;
use pnet::datalink::{interfaces, NetworkInterface};
use pcap::{Device, Address, Capture, Linktype, BpfProgram};

#[derive(Debug)]
pub struct Frame {
    srchaddr: MacAddr,
    dsthaddr: MacAddr,
    ethertype: u16,
    payload: Vec<u8>, 
}

impl Frame {
    pub fn new() -> Frame {
        let f = Frame {
            srchaddr: MacAddr::zero(),
            dsthaddr: MacAddr::zero(),
            ethertype: 0,
            payload: vec![]
        };
        f
    }

    pub fn set_srchaddr(&mut self, srchaddr: MacAddr) -> &Frame {
        self.srchaddr = srchaddr;
        self
    }
    pub fn set_dsthaddr(&mut self, dsthaddr: MacAddr) -> &Frame {
        self.dsthaddr = dsthaddr;
        self
    }
    pub fn set_ethertype(&mut self, ethertype: u16) -> &Frame {
        self.ethertype = ethertype;
        self
    }

    pub fn set_payload(&mut self, payload: Vec<u8>) -> &Frame {
        self.payload = payload;
        self
    }
}

impl From<Frame> for Vec<u8> {
    fn from(f: Frame) -> Vec<u8> {
        let mut raw_frame = vec![];
        raw_frame.extend(f.dsthaddr.octets());
        raw_frame.extend(f.srchaddr.octets());
        raw_frame.extend(f.ethertype.to_ne_bytes());
        raw_frame.extend(f.payload);
        raw_frame

    }
}

impl From<Vec<u8>> for Frame {
    fn from(f: Vec<u8>) -> Frame {
        let mut frame = Frame::new();
        frame.set_dsthaddr(MacAddr(f[0], f[1], f[2], f[3], f[4], f[5]));
        frame.set_srchaddr(MacAddr(f[6], f[7], f[8], f[9], f[10], f[11]));
        frame.set_ethertype(u16::from_be_bytes([f[12], f[13]]));
        frame.set_payload(f[14..].to_vec());
        frame
    }
}

const ARPHRD_ETHER: u16 = 0x0001;
const ETHERTYPE_IP: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETH_ALEN: u8 = 6;
const ARP_PROTO_LEN: u8 = 4;
const ARPOP_REQUEST: u16 = 0x0001;

#[derive(Debug)]
struct ArpHeader {
    ar_hrd: u16,
    ar_pro: u16,
    ar_hln: u8,
    ar_pln: u8,
    ar_op: u16,
}

const ARP_HEADER: ArpHeader = ArpHeader {
    ar_hrd: ARPHRD_ETHER,
    ar_pro: ETHERTYPE_IP,
    ar_hln: ETH_ALEN,
    ar_pln: ARP_PROTO_LEN,
    ar_op: ARPOP_REQUEST,
};

#[derive(Debug)]
pub struct ArpFrame {
    arphdr: ArpHeader,
    srchaddr: MacAddr,
    srcip: Ipv4Addr,
    dsthaddr: MacAddr,
    dstip: Ipv4Addr,
    zero_padding: [u8; 18],
}

impl ArpFrame {
    pub fn new() -> ArpFrame {
        let af = ArpFrame {
            arphdr: ARP_HEADER,
            srchaddr: MacAddr::zero(),
            srcip: Ipv4Addr::UNSPECIFIED,
            dsthaddr: MacAddr::zero(),
            dstip: Ipv4Addr::UNSPECIFIED,
            zero_padding: [0u8; 18],
        };
        af
    }

    pub fn set_srchaddr(&mut self, srchaddr: MacAddr) -> &ArpFrame {
        self.srchaddr = srchaddr;
        self
    }
    pub fn set_srcip(&mut self, srcip: Ipv4Addr) -> &ArpFrame {
        self.srcip = srcip;
        self
    }
    pub fn set_dsthaddr(&mut self, dsthaddr: MacAddr) -> &ArpFrame {
        self.dsthaddr = dsthaddr;
        self
    }
    pub fn set_dstip(&mut self, dstip: Ipv4Addr) -> &ArpFrame {
        self.dstip = dstip;
        self
    }
}

impl From<ArpFrame> for Vec<u8> {
    fn from(f: ArpFrame) -> Vec<u8> {
        let mut arp_frame = vec![];
        arp_frame.extend(f.arphdr.ar_hrd.to_be_bytes());
        arp_frame.extend(f.arphdr.ar_pro.to_be_bytes());
        arp_frame.extend(f.arphdr.ar_hln.to_be_bytes());
        arp_frame.extend(f.arphdr.ar_pln.to_be_bytes());
        arp_frame.extend(f.arphdr.ar_op.to_be_bytes());
        arp_frame.extend(f.srchaddr.octets());
        arp_frame.extend(f.srcip.octets());
        arp_frame.extend(f.dsthaddr.octets());
        arp_frame.extend(f.dstip.octets());
        arp_frame.extend(f.zero_padding);
        arp_frame
    }
}

fn forge_arp_frame (eth_src: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = Frame::new();
    frame.set_srchaddr(eth_src);
    frame.set_dsthaddr(MacAddr::broadcast());
    frame.set_ethertype(ETHERTYPE_ARP.to_be());

    let mut arp_frame = ArpFrame::new();
    arp_frame.set_srchaddr(eth_src); 
    arp_frame.set_srcip(src_ip);
    arp_frame.set_dsthaddr(MacAddr::broadcast()); 
    arp_frame.set_dstip(dst_ip); 

    frame.set_payload(arp_frame.into());
    frame.into()

}
fn forge_frame(src: MacAddr, dst: MacAddr, payload: Vec<u8>) -> Vec<u8> {

    let mut frame = Frame::new();
    frame.set_srchaddr(src);
    frame.set_dsthaddr(dst);
    frame.set_ethertype(ETHERTYPE_IP.to_be());
    frame.set_payload(payload);
    frame.into()
    
}
// Return a Device, given the name
fn get_local_mac_address(name: String) -> Option<MacAddr> {
    match interfaces().into_iter().filter(|x| x.name == name).next() {
        Some(dev) => dev.mac,
        _ => None
    }
}

/// Get the interface from the local ip
fn get_interface_by_ip (local_addr: IpAddr) -> Option<Device> {

    let fake_ip = Address {
        addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        broadcast_addr: None,
        netmask: None,
        dst_addr: None    
    };
    

    let ip_match = |ip: &Address| {
        //println!("{:?}", ip);
        ip.addr.eq(&local_addr)
    };

    match Device::list() {
        Ok(devices) => devices.into_iter().filter(|x| local_addr == (x.addresses.clone().into_iter().filter(ip_match)).next().unwrap_or(fake_ip.to_owned()).addr).next(),
        _ => None
    }
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

fn recv_frame (cap: &mut Capture<pcap::Active>, filter: &String) -> Frame {

    let f = Frame::new();

    let p = match cap.filter(filter, true){
        Ok(_) => cap.next_packet(),
        Err(e) => {
            println!("rf er {:?}", e);
            return f
        }
    }; 
    match p {
        Ok(packet) => {
            println!("rf {:?}", packet);
            packet.data.to_vec().into()},
        _ => f,
    }

}
fn send_frame(frame: &[u8], iface: &Device, filter: Option<&String> ) -> Frame
{

    let mut capture_dev = match Capture::from_device(iface.clone()) {
        Ok(c) => match c.promisc(true).timeout(10).snaplen(5000).open() {
            Ok(mut capture) =>     {
                capture.sendpacket(frame);
                capture
            }
            Err(_) => return Frame::new(),
        }
        Err(_) => return Frame::new(),
    };


    match filter {
        Some(f) => recv_frame (&mut capture_dev, f),
        _ => Frame::new()
    }    
}

fn send_raw_arp()
{
   
    let arp_p = [0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0x28u8, 0xdfu8, 0xebu8, 0x2bu8, 0x7du8, 0x11u8, 0x08u8, 0x06u8, 0x00u8, 0x01,
                     0x08u8, 0x00u8, 0x06u8, 0x04u8, 0x00u8, 0x01u8, 0x28u8, 0xdfu8, 0xebu8, 0x2bu8, 0x7du8, 0x11u8, 0xc0u8, 0xa8u8, 0x00u8, 0x01,
                     0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xc0u8, 0xa8u8, 0x00u8, 0x01u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00,
                     0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00].to_vec();
    
    
    // Get the interface which will be used for sending the frame through.
    let current_target = Ipv4Addr::new(192, 168, 0, 1);
    let local_ip = match get_source_ip(IpAddr::V4(current_target), 50000u32) {
        Some(x) => x.ip(),
        _ => return (),
    };
    let iface = match get_interface_by_ip(local_ip) {
        Some(iface) => iface,
        _ => return ()
    };
        
    let filter = "arp and src 192.168.0.1".to_string();
    send_frame(&arp_p, &iface, Some(&filter));
}


// Invoke as echo <interface name>
fn main() {

    let src = MacAddr(0x28, 0xdf, 0xeb, 0x2b, 0x7d, 0x11);
    //let src = MacAddr(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
    //let dst = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let dst = MacAddr(0xdc, 0x53, 0x7c, 0x4f, 0xcd, 0x68);
    let payload: Vec<u8> = "abcd".as_bytes().to_vec();

    // Get the interface which will be used for sending the frame through.
    let current_target = Ipv4Addr::new(192, 168, 0, 1);
    let local_ip = match get_source_ip(IpAddr::V4(current_target), 50000u32) {
        Some(x) => x,
        _ => return (),
    };

    let ip = match local_ip.ip() {
        IpAddr::V4(ip) => {
            let oct = ip.octets();
            Ipv4Addr::new(oct[0], oct[1], oct[2], oct[3])               
        },
        _ => return
    };

    
    let iface = match get_interface_by_ip(local_ip.ip()) {
        Some(iface) => iface,
        _ => return ()
    };

    
    // forge the frame
    //let frame = forge_frame (src, dst, payload);
    //println!("FRAME {:?}", frame);

    // Send the frame
    //let filter = "dst host 192.168.0.91 and src host 192.168.0.1".to_string();
    //send_frame(&frame, &iface, Some(&filter));

    let filter = "arp or rarp".to_string();
    let arp_frame = forge_arp_frame(src, ip , current_target);
    let recv_f = send_frame(&arp_frame, &iface, Some(&filter)); 
    println!("Recv Frame {:?}",recv_f);

    
    println!("local mac{:?}", get_local_mac_address(get_interface_by_ip(local_ip.ip()).unwrap().name));
   
}


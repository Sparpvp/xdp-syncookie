#![no_std]
#![no_main]

use core::convert::TryFrom;
use core::hash::{Hash, Hasher, SipHasher};
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

struct Transport(*mut tcphdr);

impl Transport {
    fn is_syn(&self) -> bool {
        unsafe { *self.0 }.syn() == 1
    }

    fn is_ack(&self) -> bool {
        unsafe { *self.0 }.ack() == 1
    }

    fn set_tcpseq(&mut self, tcpseq: u32) {
        unsafe { *self.0 }.ack_seq = tcpseq
    }

    fn get_tcpseq(&self) -> u32 {
        unsafe { *self.0 }.seq
    }

    fn process_syn(
        &self,
        // ctx: &XdpContext,
        ip_proto: &IPProtocol,
        eth_h: *mut ethhdr, // eth_h is retrievable with ctx
    ) -> XdpResult {
        let tcph = self.0;

        unsafe {
            // Reverse TCP ports
            let temp_s_port = (*tcph).source;
            (*tcph).source = (*tcph).dest;
            (*tcph).dest = temp_s_port;

            // Reverse IP pointer
            match *ip_proto {
                IPProtocol::IPv4(ipv4h) => {
                    let ipv4h = ipv4h as *mut iphdr;

                    let temp_ipv4_saddr = (*ipv4h).saddr;
                    (*ipv4h).saddr = (*ipv4h).daddr;
                    (*ipv4h).daddr = temp_ipv4_saddr;
                }
                IPProtocol::IPv6(ipv6h) => {
                    let ipv6h = ipv6h as *mut ipv6hdr;

                    let temp_ipv6_saddr = (*ipv6h).saddr;
                    (*ipv6h).saddr = (*ipv6h).daddr;
                    (*ipv6h).daddr = temp_ipv6_saddr;
                }
            }

            // Reverse Ethernet direction
            let eth_h_source = (*eth_h).h_source;
            (*eth_h).h_source = (*eth_h).h_dest;
            (*eth_h).h_dest = eth_h_source;

            /* TODO process_syn:
                [x] Generate SYN Cookie
                [x] Clear IP options
                [x] Update IP checksum
                [x] Update TCP checksum
            */
        };

        Ok(XdpAction::Tx)
    }

    fn process_ack(&self) -> XdpResult {
        todo!()
    }

    fn handle_tcp(&self, ip_proto: &IPProtocol, eth_h: *mut ethhdr) -> XdpResult {
        let syn = self.is_syn();
        printk!("Syn: %u", syn as u32).unwrap();

        match syn {
            true => self.process_syn(&ip_proto, eth_h),
            false if self.is_ack() == true => self.process_ack(),
            _ => Ok(XdpAction::Pass),
        }
    }
}

#[derive(Hash)]
struct Cookie {
    server_ip: u32,
    client_ip: u32,
    server_port: u16,
    client_port: u16,
    timestamp: u8,
}

/*
    Syn Cookie Model:
    - 8 bits timestamp t
    - 24 bits checksum s

    MSS is ignored in my implementation since the networking stack will ignore it.
*/
struct TCPSequence {
    timestamp: u8,
    //mss: u8,
    checksum: u64,
}

impl TCPSequence {
    fn build_tcp_sequence(&self) -> u32 {
        let mut tcp_seq: u32 = 0;
        tcp_seq = (tcp_seq << 8) | self.timestamp as u32;
        tcp_seq = (tcp_seq << 24) | (self.checksum >> 32) as u32;

        tcp_seq
    }
}

fn generate_syn_cookie(ip_proto: &IPProtocol, tcph: *const tcphdr) -> u32 {
    const NS_TO_S: u64 = 1000000000;

    let mut tcp_seq: u32 = 0;
    let t = ((bpf_ktime_get_ns() / NS_TO_S) >> 6) as u8;
    //printk!("timestamp 64s resolution: %u", t);
    let (source_addr, dest_addr) = match *ip_proto {
        IPProtocol::IPv4(ipv4h) => unsafe { ((*ipv4h).saddr, (*ipv4h).daddr) },
        IPProtocol::IPv6(ipv6h) => unsafe {
            // ((*ipv6h).saddr, (*ipv6h).daddr) // different type...
            todo!()
        },
    };
    let (source_port, dest_port) = unsafe { ((*tcph).source, (*tcph).dest) };

    let mut hasher = SipHasher::new(); // Todo: use better hasher
    let cookie = Cookie {
        server_ip: source_addr,
        server_port: source_port,
        client_ip: dest_addr,
        client_port: dest_port,
        timestamp: t,
    };
    cookie.hash(&mut hasher);
    let hash = hasher.finish();

    let tcp_sequence = TCPSequence {
        timestamp: t,
        checksum: hash,
    };
    let tcp_sequence = tcp_sequence.build_tcp_sequence();
    printk!("TCP Sequence: %u", tcp_sequence);

    tcp_sequence
}

enum IPProtocol {
    IPv4(*const iphdr),
    IPv6(*const ipv6hdr),
}

impl IPProtocol {
    fn tcp(&self, ctx: &XdpContext) -> Result<Transport, NetworkError> {
        let tcp_ptr: *const tcphdr = match *self {
            IPProtocol::IPv4(iph) if unsafe { *iph }.protocol == IPPROTO_TCP as u8 => {
                let addr = unsafe { iph as usize + ((*iph).ihl() * 4) as usize };
                unsafe { ctx.ptr_at(addr)? }
            }
            IPProtocol::IPv6(ipv6h) if unsafe { *ipv6h }.nexthdr == IPPROTO_TCP as u8 => {
                let addr = ipv6h as usize + 40;
                unsafe { ctx.ptr_at(addr)? }
            }
            _ => return Err(NetworkError::Other),
        };

        Ok(Transport(tcp_ptr as *mut _))
    }
}

impl TryFrom<&XdpContext> for IPProtocol {
    type Error = NetworkError;

    fn try_from(ctx: &XdpContext) -> Result<Self, Self::Error> {
        let eth = ctx.eth()?;

        // EtherType is a two octet field which indicates which protocol is encapsulated in the payload of the frame
        let ethertype = unsafe { *eth }.h_proto as u32;

        // Adjust endianness
        let eth_ipv4 = u16::from_be(ETH_P_IP as u16);
        let eth_ipv6 = u16::from_be(ETH_P_IPV6 as u16);

        //printk!("[DBG] Got EtherType: 0x%x %x", ethertype, eth_ipv4).unwrap();

        // Get pointer to next header
        // let network_layer = (eth as usize) + size_of::<ethhdr>(); // redbpf fix ur trash

        match ethertype {
            ipv4 if ipv4 as u16 == eth_ipv4 => unsafe { Ok(IPProtocol::IPv4(ctx.ptr_after(eth)?)) },
            ipv6 if ipv6 as u16 == eth_ipv6 => unsafe { Ok(IPProtocol::IPv6(ctx.ptr_after(eth)?)) },
            _ => Err(NetworkError::NoIPHeader),
        }
    }
}

#[xdp]
pub fn xdp_main(ctx: XdpContext) -> XdpResult {
    let ip_proto = IPProtocol::try_from(&ctx)?;

    // Debuggy way:
    // let is_syn = match ipproto {
    //     Ok(ipproto @ IPProtocol::IPv4(_)) => {
    //         let tcp = ipproto.tcp(&ctx);
    //         let tcp = match tcp {
    //             Ok(_) => tcp,
    //             Err(e) => {
    //                 printk!("Error in tcp function call");
    //                 Err(e)
    //             }
    //         };

    //         Ok(tcp?.is_syn())
    //     }
    //     Ok(ipproto @ IPProtocol::IPv6(_)) => {
    //         let tcp = ipproto.tcp(&ctx);
    //         let tcp = match tcp {
    //             Ok(_) => tcp,
    //             Err(e) => {
    //                 printk!("Error in tcp function call");
    //                 Err(e)
    //             }
    //         };

    //         Ok(tcp?.is_syn())
    //     }
    //     Err(e) => {
    //         printk!("No IP Header");
    //         Err(e)
    //     }
    // };

    let tcp = ip_proto.tcp(&ctx)?;

    // Should i lookup listener socket?

    let eth = ctx.eth()? as *mut ethhdr;

    todo!();
    //let xdpaction = tcp.handle_tcp(&ip_proto, eth);
    //let sequence = generate_syn_cookie(&ip_proto, tcp.0);

    //return xdpaction;
    //Ok(XdpAction::Pass)
}

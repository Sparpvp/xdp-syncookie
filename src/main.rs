#![no_std]
#![no_main]

use core::convert::TryFrom;
use core::hash::{Hash, Hasher, SipHasher};
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

const NS_TO_S: u64 = 1000000000;

fn get_checksum<T: Hash>(to_hash: T) -> u32 {
    let mut hasher = SipHasher::new(); // todo: use better hash
    to_hash.hash(&mut hasher);
    hasher.finish() as u32
}

// TODO: Use this to support IPv4 AND IPv6 address in match operation (unaccepted due to different types)
// enum Address {
//     IPv4Addr(u32),
//     IPv6Addr(in6_addr),
// }

struct Transport(*mut tcphdr);

impl Transport {
    fn is_syn(&self) -> bool {
        unsafe { *self.0 }.syn() == 1
    }

    fn is_ack(&self) -> bool {
        unsafe { *self.0 }.ack() == 1
    }

    fn process_syn(&self, ip_proto: &IPProtocol, eth_h: *mut ethhdr) -> XdpResult {
        let tcph = self.0;

        unsafe {
            // Send SYN Cookie in SYN-ACK
            let cookie = Cookie::generate_syn_cookie(&ip_proto, tcph);
            (*tcph).ack_seq = (*tcph).seq + 1;
            (*tcph).seq = cookie;
            (*tcph).set_ack(1);

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
                [x] Clear IP options
                [x] Update IP checksum
                [x] Update TCP checksum
            */
        };

        Ok(XdpAction::Tx)
    }

    fn process_ack(&self, ip_proto: &IPProtocol) -> XdpResult {
        let tcph = self.0;

        unsafe {
            let received_cookie = ((*tcph).seq) - 1;
            printk!("Received sequence number: %u", received_cookie);
            let (t, recv_hash) = Cookie::retrive_tcp_sequence(received_cookie);
            printk!("T: %u", t);

            // Recompute checksum
            let (saddr, daddr) = match *ip_proto {
                IPProtocol::IPv4(ipv4h) => ((*ipv4h).saddr, (*ipv4h).daddr),
                IPProtocol::IPv6(ipv6h) => todo!(),
            };
            let checksum = CookieChecksum {
                server_port: (*tcph).source,
                client_port: (*tcph).dest,
                timestamp: t,
                server_ip: saddr,
                client_ip: daddr,
            };
            let checksum = get_checksum(checksum) / 520;

            printk!("Hash recomputed: %u | TCP hash: %u", checksum, recv_hash);

            let actual_timestamp = ((bpf_ktime_get_ns() / NS_TO_S) >> 6) as u8;
            if checksum == recv_hash && t == actual_timestamp {
                return Ok(XdpAction::Pass);
            } else {
                return Ok(XdpAction::Drop);
            }
        }
    }

    fn handle_tcp(&self, ip_proto: &IPProtocol, eth_h: *mut ethhdr) -> XdpResult {
        let syn = self.is_syn();
        //printk!("Syn: %u", syn as u32).unwrap();

        match syn {
            true => self.process_syn(&ip_proto, eth_h),
            false if self.is_ack() == true => self.process_ack(&ip_proto),
            _ => Ok(XdpAction::Pass),
        }
    }
}

#[derive(Hash)]
struct CookieChecksum {
    server_ip: u32,
    client_ip: u32,
    server_port: u16,
    client_port: u16,
    timestamp: u8,
}

/*
    SYN Cookie model:
    - 8 bits timestamp t
    - 24 bits checksum s

    MSS is ignored in my implementation since the networking stack will ignore it.
*/
struct Cookie {
    timestamp: u8,
    checksum: u32,
}

impl Cookie {
    fn build_tcp_sequence(&self) -> u32 {
        let mut tcp_seq: u32 = 0;
        tcp_seq = (tcp_seq << 8) | self.timestamp as u32;
        tcp_seq = (tcp_seq << 24) | (self.checksum / 520);
        // Note: / 520 is just a rough estimate to fit the biggest u32 into a 24 bits, should improve this.

        tcp_seq
    }

    fn retrive_tcp_sequence(seq_num: u32) -> (u8, u32) {
        let t = ((seq_num >> 24) & 0xFF) as u8;
        let checksum = seq_num & 0xFFFFFF;

        (t, checksum)
    }

    fn generate_syn_cookie(ip_proto: &IPProtocol, tcph: *const tcphdr) -> u32 {
        let t = ((bpf_ktime_get_ns() / NS_TO_S) >> 6) as u8;
        let (source_addr, dest_addr) = match *ip_proto {
            IPProtocol::IPv4(ipv4h) => unsafe { ((*ipv4h).saddr, (*ipv4h).daddr) },
            IPProtocol::IPv6(ipv6h) => unsafe {
                // ((*ipv6h).saddr, (*ipv6h).daddr) // different type...
                printk!("Unimplemented! IPv6");
                todo!()
            },
        };
        let (source_port, dest_port) = unsafe { ((*tcph).source, (*tcph).dest) };

        let csum = CookieChecksum {
            server_ip: source_addr,
            server_port: source_port,
            client_ip: dest_addr,
            client_port: dest_port,
            timestamp: t,
        };
        let csum = get_checksum(csum);

        let tcp_sequence = Cookie {
            timestamp: t,
            checksum: csum,
        };
        let tcp_sequence = tcp_sequence.build_tcp_sequence(); // fits different types in determined number of bytes

        printk!("Generated TCP Sequence: %u", tcp_sequence);
        //let (tt, cc) = Cookie::retrive_tcp_sequence(tcp_sequence);
        //assert_eq!(csum / 520, cc); // PASS
        //printk!("csum g: %u | csum got: %u", csum / 520, cc);

        tcp_sequence
    }
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
    let tcp = ip_proto.tcp(&ctx)?;
    let eth = ctx.eth()? as *mut ethhdr;

    let XdpState = tcp.handle_tcp(&ip_proto, eth);

    match &XdpState {
        Ok(XdpAction::Pass) => {
            printk!("Action: Pass");
        }
        Ok(XdpAction::Tx) => {
            printk!("Action: TX");
        }
        Ok(XdpAction::Drop) => {
            printk!("Action: Drop");
        }
        _ => {
            unreachable!();
        }
    }

    XdpState
}

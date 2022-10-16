use std::{collections::HashMap, io, net::Ipv4Addr};

mod tcp;

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy)]
struct Quad {
    // ip and port
    src: (Ipv4Addr, u16),
    dest: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::State> = Default::default();

    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Everything failed");
    let mut buf = [0u8; 1504];

    loop {
        let n_bytes = nic.recv(&mut buf[..])?;

        let _flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);

        // this protocol is the ethernet protocol
        if proto != 0x0800 {
            // ignore any packets that is not an ipv4 packet
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..n_bytes]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dest = ip_header.destination_addr();
                // this is the IP level protocol
                let protocol = ip_header.protocol();

                if protocol != 0x06 {
                    // not a tcp packet
                    continue;
                }

                let ip_header_size = ip_header.slice().len();

                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + ip_header.slice().len()..n_bytes]) {
                    Ok(tcp_header) => {
                        let tcp_header_size = tcp_header.slice().len();

                        let data_index = 4 + ip_header_size + tcp_header_size;
                        // (srcip, srcport, destip, destport)

                        connections
                            .entry(Quad {
                                src: (src, tcp_header.source_port()),
                                dest: (dest, tcp_header.destination_port()),
                            })
                            .or_default()
                            .on_packet(ip_header, tcp_header, &buf[data_index..n_bytes]);
                    }
                    Err(e) => {
                        println!("TcpHeaderSlice parse failed {:?}", e);
                        // just to get rid of annoying warning
                        break;
                    }
                }
            }

            Err(e) => {
                println!("Ignoring weird packet {:?}", e);
            }
        }
    }

    Ok(())
}

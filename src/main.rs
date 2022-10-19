use std::{collections::HashMap, io, net::Ipv4Addr};

mod tcp;

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy)]
struct Quad {
    // ip and port
    src: (Ipv4Addr, u16),
    dest: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();

    let mut nic =
        tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun).expect("Everything failed");
    let mut buf = [0u8; 1504];

    loop {
        let n_bytes = nic.recv(&mut buf[..])?;

        // let _flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let proto = u16::from_be_bytes([buf[2], buf[3]]);

        // // this protocol is the ethernet protocol
        // if proto != 0x0400 {
        //     println!("Not an ipv4 packet");
        //     // ignore any packets that is not an ipv4 packet
        //     continue;
        // }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..n_bytes]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dest = ip_header.destination_addr();
                // this is the IP level protocol
                let protocol = ip_header.protocol();

                if protocol != 0x06 {
                    eprintln!("Not a TCP packet");
                    // not a tcp packet
                    continue;
                }

                let ip_header_size = ip_header.slice().len();

                match etherparse::TcpHeaderSlice::from_slice(&buf[ip_header.slice().len()..n_bytes])
                {
                    Ok(tcp_header) => {
                        use std::collections::hash_map::Entry;

                        let tcp_header_size = tcp_header.slice().len();

                        let data_index = ip_header_size + tcp_header_size;
                        // (srcip, srcport, destip, destport)

                        match connections.entry(Quad {
                            src: (src, tcp_header.source_port()),
                            dest: (dest, tcp_header.destination_port()),
                        }) {
                            Entry::Occupied(mut existing_conn) => {
                                eprintln!("Occupied: src {}, dest {}", src, dest);
                                existing_conn.get_mut().on_packet(
                                    &mut nic,
                                    ip_header,
                                    tcp_header,
                                    &buf[data_index..n_bytes],
                                )?;
                            }
                            Entry::Vacant(e) => {
                                eprintln!("Error: src {}, dest {}", src, dest);
                                if let Some(conn) = tcp::Connection::accept(
                                    &mut nic,
                                    ip_header,
                                    tcp_header,
                                    &buf[data_index..n_bytes],
                                )? {
                                    e.insert(conn);
                                }
                            }
                        }
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

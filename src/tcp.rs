use std::io;

enum State {
    // Closed,
    // Listen,
    SynRecvd,
    Estab,
}

// Transission Control Block
// the state's that's kept for every TCP request
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip_packet: etherparse::Ipv4Header,
}

/// State of the Send Sequence Space
/// ```
///            1         2          3          4      
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA        
///                                   +SND.WND        
///
/// 1 - old sequence numbers which have been acknowledged  
/// 2 - sequence numbers of unacknowledged data            
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed  
///
///                   Send Sequence Space
///
///                        Figure 4.
///
/// The send window is the portion of the sequence space labeled 3 in
/// figure 4.
/// ```
pub struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

/// Receive Sequence Space
///
///                 1          2          3      
///             ----------|----------|----------
///                    RCV.NXT    RCV.NXT        
///                              +RCV.WND        
///
///  1 - old sequence numbers which have been acknowledged  
///  2 - sequence numbers allowed for new reception         
///  3 - future sequence numbers which are not yet allowed  
///
///                   Receive Sequence Space
///
///                         Figure 5.
///
///
///
/// The receive window is the portion of the sequence space labeled 2 in
/// figure 5.
pub struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface, // just for now
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];

        eprintln!(
            "{}:{} → {}:{} {}b of tcp",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len()
        );

        let iss = 0;

        let mut conn = Connection {
            state: State::SynRecvd,

            // decide on stuff we're sending them
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,
                wl1: 0,
                wl2: 0,
            },

            // keep track of sender info
            recv: RecvSequenceSpace {
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                irs: tcp_header.sequence_number(),
                up: false,
            },

            ip_packet: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                [
                    ip_header.destination()[0],
                    ip_header.destination()[1],
                    ip_header.destination()[2],
                    ip_header.destination()[3],
                ],
                [
                    ip_header.source()[0],
                    ip_header.source()[1],
                    ip_header.source()[2],
                    ip_header.source()[3],
                ],
            ),
        };

        // if the syn bit is not set
        if !tcp_header.syn() {
            // only expected syn packet
            return Ok(None);
        }

        // got a syn, need to start establishing a connection
        // sending back a syn ack so destination_port is the source_port now and
        // source_port is the destination_port
        let mut syn_ack = etherparse::TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            // sequence number is random
            conn.send.iss,
            conn.send.wnd,
        );

        // the acknowledgment_number is the next byte we're expecting to get from the other
        // side
        syn_ack.acknowledgment_number = conn.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        conn.ip_packet
            .set_payload_len(syn_ack.header_len() as usize + 0);

        // The Kernel does this for us
        // syn_ack.checksum = syn_ack.calc_checksum_ipv4(&ip_packet, &[]).expect("Failed to compute checksum");

        // write out the headers
        let unwritten = {
            let mut unwritten = &mut buf[..];
            conn.ip_packet.write(&mut unwritten);
            syn_ack.write(&mut unwritten);

            unwritten.len()
        };

        nic.send(&buf[..buf.len() - unwritten]);

        return Ok(Some(conn));
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface, // just for now
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // first check that sequence numbers are valid

        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // have to deal with wrapping arithmetic

        let ackn = tcp_header.acknowledgment_number();

        match self.state {
            State::SynRecvd => {
                // expect to get an ACK for our SYN
            }
            State::Estab => {
                unimplemented!("State::Estab");
            }
        }

        Ok(())
    }
}

fn is_between_wrapped(start: usize, x: usize, end: usize) -> bool {
    if self.send.una < ackn {
        // check is violated iff N is between U and A
        if self.send.nxt >= self.send.una && self.send.nxt < ackn {
            return false;
        }
    } else {
        // check is ok iff N is between U and A
        if self.send.nxt >= ackn && self.send.nxt < self.send.una {
            return true;
        } else {
            return false;
        }
    }
}

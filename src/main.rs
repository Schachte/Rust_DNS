mod packet;
use std::fs::File;
use std::io::Read;
use std::net::UdpSocket;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    // Perform an A query for google.com
    let qname = "cloudflare.com";
    let qtype = packet::query::QueryType::A;

    // Using googles public DNS server
    let server = ("1.1.1.1", 53);

    // Bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut dns_packet = packet::packet::DnsPacket::new();

    dns_packet.header.id = 6666;
    dns_packet.header.questions = 1;
    dns_packet.header.recursion_desired = true;
    dns_packet
        .questions
        .push(packet::question::DnsQuestion::new(qname.to_string(), qtype));

    // Use our new write method to write the packet to a buffer...
    let mut req_buffer = packet::packet::BytePacketBuffer::new();
    dns_packet.write(&mut req_buffer)?;

    // ...and send it off to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer = packet::packet::BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    // As per the previous section, `DnsPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response.
    let res_packet = packet::packet::DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:#?}", q);
    }
    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
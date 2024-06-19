use std::net::{Ipv4Addr, UdpSocket};
use std::io;
use cache::cache::{DnsCacheEntry, ThreadSafeDnsCache};
use log::{info, error};
use flexi_logger::{Logger, FileSpec, Duplicate};


use utils::byte_buffer::ByteBuffer;
use utils::packet::DnsPacket;
use utils::query_type::QueryType;
use utils::question::DnsQuestion;
use utils::record::DnsRecord;
use utils::result_code::ResultCode;

pub mod utils;
pub mod cache;

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;
    let cache = ThreadSafeDnsCache::new(2, std::time::Duration::from_millis(20));
    Logger::try_with_str("info").unwrap()
        .log_to_file(FileSpec::default().directory("logs"))
        .duplicate_to_stderr(Duplicate::All)
        .start()
        .unwrap();

    info!("Server started on port 2053");

    loop {
        match handle_query(socket.try_clone()?, &cache) {
            Ok(packet) => {
                info!("Query {:?} handled successfully", packet.header.id);
                for rec in packet.answers {
                    info!("{:?}", rec);
                }
                for rec in packet.authorities {
                    info!("{:?}", rec);
                }
                for rec in packet.resources {
                    info!("{:?}", rec);
                }
            }
            Err(e) => {
                error!("Error handling query: {:?}", e);
            }
        }
    }
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> io::Result<DnsPacket> {
    let mut root_server = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    loop {
        let copy = root_server;
        let server = (copy, 53);

        let res = lookup(qname, qtype, server)?;

        if res.answers.len() > 0 && res.header.rescode == ResultCode::NOERROR {
            return Ok(res);
        }

        if res.answers.is_empty() && res.header.rescode == ResultCode::NXDOMAIN {
            return Ok(res);
        }

        if let Some(addr) = res.get_resolved_ns(qname) {
            root_server = addr;
            continue;
        }

        let new_qname = match res.get_unresolved_ns(qname) {
            Some(cname) => cname,
            None => return Ok(res),
        };

        let rec = recursive_lookup(&new_qname, QueryType::A)?;
        if let Some(ns) = rec.get_random_a() {
            root_server = ns;
            continue;
        } else {
            return Ok(res);
        }
    }
}

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> io::Result<DnsPacket> {

    let socket = match UdpSocket::bind(("0.0.0.0", 43210)) {
        Ok(s) => s,
        Err(e) => {
            return Err(e);
        }
    };

    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = ByteBuffer::new();
    packet.write(&mut req_buffer).unwrap();

    socket.send_to(&req_buffer.buffer[0..req_buffer.position], server).unwrap();

    let mut res_buffer = ByteBuffer::new();
    socket.recv_from(&mut res_buffer.buffer).unwrap();

    let res_packet = DnsPacket::from_buffer(&mut res_buffer).unwrap();

    Ok(res_packet)

}

fn handle_query(socket: UdpSocket, cache: &ThreadSafeDnsCache) -> io::Result<DnsPacket> {
    let mut req_buffer = ByteBuffer::new();
    let (_, src) = socket.recv_from(&mut req_buffer.buffer).unwrap();
    let mut request = DnsPacket::from_buffer(&mut req_buffer).unwrap();

    let mut response = DnsPacket::new();
    response.header.id = request.header.id;
    response.header.recursion_desired = true;
    response.header.recursion_available = true;
    response.header.response = true;

    if let Some(q) = request.questions.pop() {

        let key = format!("{}-{:?}", q.name, q.qtype.to_num());
        if let Some(entry) = cache.get(&key) {
            // println!("Cache hit for {:?}", q);
            let mut response = entry.get_packet().unwrap();

            response.header.id = request.header.id;

            let mut res_buffer = ByteBuffer::new();
            response.write(&mut res_buffer).unwrap();
            socket.send_to(&res_buffer.buffer[0..res_buffer.position], src).unwrap();
            return Ok(response);
        }

        if let Ok(result) = recursive_lookup(&q.name, q.qtype) {
            response.questions.push(q);
            response.header.rescode = result.header.rescode;

            for rec in result.answers {
                // println!("Answer: {:?}", rec);
                response.answers.push(rec);
            }
            for rec in result.authorities {
                // println!("Authority: {:?}", rec);
                response.authorities.push(rec);
            }
            for rec in result.resources {
                // println!("Resource: {:?}", rec);
                response.resources.push(rec);
            }
        } else {
            response.header.rescode = ResultCode::SERVFAIL;
        }
    } else {
        response.header.rescode = ResultCode::FORMERR;
    }

    let mut res_buffer = ByteBuffer::new();
    response.write(&mut res_buffer).unwrap();
    socket.send_to(&res_buffer.buffer[0..res_buffer.position], src).unwrap();

    let ttl = match response.answers.get(0) {
        Some(rec) => {
            match rec {
                DnsRecord::A { ttl, .. } => *ttl,
                DnsRecord::AAAA { ttl, .. } => *ttl,
                DnsRecord::CNAME { ttl, .. } => *ttl,
                DnsRecord::NS { ttl, .. } => *ttl,
                DnsRecord::MX { ttl, .. } => *ttl,
                DnsRecord::UNKNOWN { ttl, .. } => *ttl,
            }
        }
        None => 60,
    } as u32;

    let entry = DnsCacheEntry::from_packet(&response, ttl)?;
    cache.insert(format!("{}-{:?}", response.questions[0].name, response.questions[0].qtype.to_num()), entry).unwrap();

    return Ok(response)

}
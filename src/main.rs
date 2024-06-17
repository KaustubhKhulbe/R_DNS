use std::net::UdpSocket;
use std::io;
use clap::{Arg, Command};
use log::{info, error};
use flexi_logger::{Logger, FileSpec, Duplicate};

use utils::byte_buffer::ByteBuffer;
use utils::packet::DnsPacket;
use utils::query_type::QueryType;
use utils::question::DnsQuestion;

pub mod utils;

fn main() -> io::Result<()> {
    let matches = Command::new("dns_query")
        .version("1.0")
        .about("Performs a DNS query")
        .arg(Arg::new("log")
            .short('l')
            .long("log")
            .takes_value(false)
            .help("Enable logging to file"))
        .get_matches();

    let enable_logging = matches.is_present("log");

    if enable_logging {
        Logger::try_with_str("info").unwrap()
            .log_to_file(FileSpec::default().directory("logs"))
            .duplicate_to_stderr(Duplicate::All)
            .start()
            .unwrap();
        info!("Logging is enabled.");
    }

    let qname = "yahoo.com";
    let qtype = QueryType::A;

    if enable_logging {
        info!("Starting DNS query for {} with type {:?}", qname, qtype);
    }

    // Using Google's public DNS server
    let server = ("8.8.8.8", 53);

    // Bind a UDP socket to an arbitrary port
    let socket = match UdpSocket::bind(("0.0.0.0", 43210)) {
        Ok(s) => s,
        Err(e) => {
            if enable_logging {
                error!("Failed to bind socket: {}", e);
            }
            return Err(e);
        }
    };

    if enable_logging {
        info!("Socket bound to 0.0.0.0:43210");
    }

    // Build our query packet
    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = ByteBuffer::new();
    match packet.write(&mut req_buffer) {
        Ok(_) => {
            if enable_logging {
                info!("DNS query packet written successfully");
            }
        }
        Err(e) => {
            if enable_logging {
                error!("Failed to write DNS query packet: {}", e);
            }
            return Err(e);
        }
    }

    // Send it off to the server using our socket
    match socket.send_to(&req_buffer.buffer[0..req_buffer.position], server) {
        Ok(_) => {
            if enable_logging {
                info!("Query sent to server {:?}", server);
            }
        }
        Err(e) => {
            if enable_logging {
                error!("Failed to send query to server: {}", e);
            }
            return Err(e);
        }
    };

    // Prepare for receiving the response
    let mut res_buffer = ByteBuffer::new();
    match socket.recv_from(&mut res_buffer.buffer) {
        Ok(_) => {
            if enable_logging {
                info!("Response received from server");
            }
        }
        Err(e) => {
            if enable_logging {
                error!("Failed to receive response from server: {}", e);
            }
            return Err(e);
        }
    };

    // Parse the response packet
    let res_packet = match DnsPacket::from_buffer(&mut res_buffer) {
        Ok(packet) => {
            if enable_logging {
                info!("DNS response packet parsed successfully");
            }
            packet
        }
        Err(e) => {
            if enable_logging {
                error!("Failed to parse DNS response packet: {}", e);
            }
            return Err(e);
        }
    };

    // Log the response details
    if enable_logging {
        info!("{:#?}", res_packet.header);

        for q in res_packet.questions {
            info!("{:#?}", q);
        }
        for rec in res_packet.answers {
            info!("{:#?}", rec);
        }
        for rec in res_packet.authorities {
            info!("{:#?}", rec);
        }
        for rec in res_packet.resources {
            info!("{:#?}", rec);
        }
    } else {
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
    }

    Ok(())
}

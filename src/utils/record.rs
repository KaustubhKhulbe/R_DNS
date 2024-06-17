use std::{io::Result, net::{Ipv4Addr, Ipv6Addr}};
use crate::utils::byte_buffer::ByteBuffer;
use crate::QueryType;

/*
Name -- Label Sequence
Type -- 2-byte Integer
Class -- 2-byte Integer
TTL -- 4-byte Integer
Len -- 2-byte Integer
*/

/*
A: Indicates the IP address for the domain. Holds a 32-bit IPv4 address. E.g. "cloudfare.come" gives 104.17.210.9
    default TTL is 14,400 seconds so if the record gets updated, it will take 4 hours to propagate.

NS: Indicates the authoritative name server for the domain. Holds a domain name. E.g. "cloudfare.com" gives "ns1.cloudflare.com".
    NS records cannot point to CNAME records.

CNAME: Indicates the canonical name for an alias. Holds a domain name. E.g. "www.cloudflare.com" gives "www.cloudflare.com.cdn.cloudflare.net"
    e.g. "www.cloudflare.com" gives "www.cloudflare.com.cdn.cloudflare.net" which  resolves to an A record.

MX: Indicates the mail server for the domain. Holds a domain name. E.g. "cloudfare.com" gives "mail.cloudfare.com".

AAAA: Indicates the IP address for the domain. Holds a 128-bit IPv6 address.
*/
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        ns: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        cname: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        preference: u16,
        exchange: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

impl DnsRecord {
    pub fn read(buffer: &mut ByteBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;
        let qtype = buffer.read_u16()?;
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            1 => {
                let addr = Ipv4Addr::from(buffer.read_u32()?);
                Ok(DnsRecord::A {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            },
            2 => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;
                Ok(DnsRecord::NS {
                    domain: domain,
                    ns: ns,
                    ttl: ttl,
                })
            },
            5 => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;
                Ok(DnsRecord::CNAME {
                    domain: domain,
                    cname: cname,
                    ttl: ttl,
                })
            },
            15 => {
                let preference = buffer.read_u16()?;
                let mut exchange = String::new();
                buffer.read_qname(&mut exchange)?;
                Ok(DnsRecord::MX {
                    domain: domain,
                    preference: preference,
                    exchange: exchange,
                    ttl: ttl,
                })
            },
            28 => {
                let mut addr = [0u8; 16];
                for i in 0..16 {
                    addr[i] = buffer.read()?;
                }
                let addr = Ipv6Addr::from(addr);
                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            },
            _ => {
                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype,
                    data_len: data_len,
                    ttl: ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut ByteBuffer) {
        match self {
            DnsRecord::UNKNOWN { domain, qtype, ttl, .. } => {
                println!("Skipping unknown record: {} {} {}", domain, qtype, ttl)
            },
            DnsRecord::A { domain, addr, ttl } => {
                let _ = buffer.write_qname(domain);
                let _ = buffer.write_u16(QueryType::A.to_num());
                let _ = buffer.write_u16(1);
                let _ = buffer.write_u32(*ttl);
                let _ = buffer.write_u16(4);
                let _ = buffer.write_u32(u32::from(*addr));
            },
            DnsRecord::NS { domain, ns, ttl } => {
                let _ = buffer.write_qname(domain);
                let _ = buffer.write_u16(QueryType::NS.to_num());
                let _ = buffer.write_u16(1);
                let _ = buffer.write_u32(*ttl);

                let start = buffer.position();
                let _ = buffer.write_u16(0 as u16); // sets initial length to 0
                let _ = buffer.write_qname(ns);
                let len = buffer.position() - (start+2);
                let _ = buffer.set_u16(start, len as u16); // sets the length to the actual length
            },
            DnsRecord::CNAME { domain, cname, ttl } => {
                let _ = buffer.write_qname(domain);
                let _ = buffer.write_u16(QueryType::CNAME.to_num());
                let _ = buffer.write_u16(1);
                let _ = buffer.write_u32(*ttl);

                let start = buffer.position();
                let _ = buffer.write_u16(0 as u16);
                let _ = buffer.write_qname(cname);
                let len = buffer.position() - (start+2);
                let _ = buffer.set_u16(start, len as u16);
            },
            DnsRecord::MX { domain, preference, exchange, ttl } => {
                let _ = buffer.write_qname(domain);
                let _ = buffer.write_u16(QueryType::MX.to_num());
                let _ = buffer.write_u16(1);
                let _ = buffer.write_u32(*ttl);

                let start = buffer.position();
                let _ = buffer.write_u16(0 as u16);
                let _ = buffer.write_u16(*preference);
                let _ = buffer.write_qname(exchange);
                let len = buffer.position() - (start+2);
                let _ = buffer.set_u16(start, len as u16);
            },
            DnsRecord::AAAA { domain, addr, ttl } => {
                let _ = buffer.write_qname(domain);
                let _ = buffer.write_u16(QueryType::AAAA.to_num());
                let _ = buffer.write_u16(1);
                let _ = buffer.write_u32(*ttl);
                let _ = buffer.write_u16(16);

                let addr = addr.octets();
                for i in 0..16 {
                    let _ = buffer.write_u8(addr[i]);
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_to_hex_int(ip: Ipv4Addr) -> u32 {
        let octets = ip.octets();
        ((octets[0] as u32) << 24) |
        ((octets[1] as u32) << 16) |
        ((octets[2] as u32) << 8)  |
        (octets[3] as u32)
    }
    

    #[test]
    fn test_read_a_record() {
        let mut buffer = ByteBuffer::new();
        let addr = Ipv4Addr::new(127, 0, 0, 1);
        buffer.write_qname("example.com").unwrap();
        buffer.write_u16(1).unwrap();
        buffer.write_u16(1).unwrap();
        buffer.write_u32(3600).unwrap();
        buffer.write_u16(4).unwrap();
        buffer.write_u32(ipv4_to_hex_int(addr)).unwrap();
        buffer.seek(0).unwrap();

        let record = DnsRecord::read(&mut buffer).unwrap();
        assert_eq!(
            record,
            DnsRecord::A {
                domain: "example.com".to_string(),
                addr,
                ttl: 3600
            }
        );
    }

    #[test]
    fn test_read_ns_record() {
        let mut buffer = ByteBuffer::new();
        buffer.write_qname("example.com").unwrap();
        buffer.write_u16(2).unwrap();
        buffer.write_u16(1).unwrap();
        buffer.write_u32(3600).unwrap();
        buffer.write_u16(13).unwrap();
        buffer.write_qname("ns1.example.com").unwrap();
        buffer.seek(0).unwrap();

        let record = DnsRecord::read(&mut buffer).unwrap();
        assert_eq!(
            record,
            DnsRecord::NS {
                domain: "example.com".to_string(),
                ns: "ns1.example.com".to_string(),
                ttl: 3600
            }
        );
    }

    #[test]
    fn test_read_cname_record() {
        let mut buffer = ByteBuffer::new();
        buffer.write_qname("example.com").unwrap();
        buffer.write_u16(5).unwrap();
        buffer.write_u16(1).unwrap();
        buffer.write_u32(3600).unwrap();
        buffer.write_u16(13).unwrap();
        buffer.write_qname("cname.example.com").unwrap();
        buffer.seek(0).unwrap();

        let record = DnsRecord::read(&mut buffer).unwrap();
        assert_eq!(
            record,
            DnsRecord::CNAME {
                domain: "example.com".to_string(),
                cname: "cname.example.com".to_string(),
                ttl: 3600
            }
        );
    }

    #[test]
    fn test_read_mx_record() {
        let mut buffer = ByteBuffer::new();
        buffer.write_qname("example.com").unwrap();
        buffer.write_u16(15).unwrap();
        buffer.write_u16(1).unwrap();
        buffer.write_u32(3600).unwrap();
        buffer.write_u16(15).unwrap();
        buffer.write_u16(10).unwrap();
        buffer.write_qname("mx.example.com").unwrap();
        buffer.seek(0).unwrap();

        let record = DnsRecord::read(&mut buffer).unwrap();
        assert_eq!(
            record,
            DnsRecord::MX {
                domain: "example.com".to_string(),
                preference: 10,
                exchange: "mx.example.com".to_string(),
                ttl: 3600
            }
        );
    }

    #[test]
    fn test_read_aaaa_record() {
        let mut buffer = ByteBuffer::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        buffer.write_qname("example.com").unwrap();
        buffer.write_u16(28).unwrap();
        buffer.write_u16(1).unwrap();
        buffer.write_u32(3600).unwrap();
        buffer.write_u16(16).unwrap();
        buffer.write_u8(0x20).unwrap();
        buffer.write_u8(0x01).unwrap();
        buffer.write_u8(0x0d).unwrap();
        buffer.write_u8(0xb8).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x00).unwrap();
        buffer.write_u8(0x01).unwrap();
        buffer.seek(0).unwrap();

        let record = DnsRecord::read(&mut buffer).unwrap();
        assert_eq!(
            record,
            DnsRecord::AAAA {
                domain: "example.com".to_string(),
                addr,
                ttl: 3600
            }
        );

    }

    #[test]
    fn test_write_a_record() {
        let mut buffer = ByteBuffer::new();
        let record = DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(127, 0, 0, 1),
            ttl: 3600,
        };
        record.write(&mut buffer);
        buffer.seek(0).unwrap();

        let mut str = String::new();
        buffer.read_qname(&mut str).unwrap();
        assert_eq!(str, "example.com");
        assert_eq!(buffer.read_u16().unwrap(), 1);
        assert_eq!(buffer.read_u16().unwrap(), 1);
        assert_eq!(buffer.read_u32().unwrap(), 3600);
        assert_eq!(buffer.read_u16().unwrap(), 4);
        assert_eq!(buffer.read_u32().unwrap(), ipv4_to_hex_int(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_write_ns_record() {
        let record = DnsRecord::NS {
            domain: "example.com".to_string(),
            ns: "ns.example.com".to_string(),
            ttl: 3600,
        };
        let mut buffer = ByteBuffer::new();
        record.write(&mut buffer);

        buffer.seek(0).unwrap();
        let mut domain = String::new();
        buffer.read_qname(&mut domain).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(buffer.read_u16().unwrap(), 2); // QueryType::NS
        assert_eq!(buffer.read_u16().unwrap(), 1); // Class
        assert_eq!(buffer.read_u32().unwrap(), 3600); // TTL
        let data_len = buffer.read_u16().unwrap();
        assert!(data_len > 0); // Ensure data length is set correctly
        let mut ns = String::new();
        buffer.read_qname(&mut ns).unwrap();
        assert_eq!(ns, "ns.example.com");
    }

    #[test]
    fn test_write_cname_record() {
        let record = DnsRecord::CNAME {
            domain: "example.com".to_string(),
            cname: "cname.example.com".to_string(),
            ttl: 3600,
        };
        let mut buffer = ByteBuffer::new();
        record.write(&mut buffer);

        buffer.seek(0).unwrap();
        let mut domain = String::new();
        buffer.read_qname(&mut domain).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(buffer.read_u16().unwrap(), 5); // QueryType::CNAME
        assert_eq!(buffer.read_u16().unwrap(), 1); // Class
        assert_eq!(buffer.read_u32().unwrap(), 3600); // TTL
        let data_len = buffer.read_u16().unwrap();
        assert!(data_len > 0); // Ensure data length is set correctly
        let mut cname = String::new();
        buffer.read_qname(&mut cname).unwrap();
        assert_eq!(cname, "cname.example.com");
    }

    #[test]
    fn test_write_mx_record() {
        let record = DnsRecord::MX {
            domain: "example.com".to_string(),
            preference: 10,
            exchange: "mx.example.com".to_string(),
            ttl: 3600,
        };
        let mut buffer = ByteBuffer::new();
        record.write(&mut buffer);

        buffer.seek(0).unwrap();
        let mut domain = String::new();
        buffer.read_qname(&mut domain).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(buffer.read_u16().unwrap(), 15); // QueryType::MX
        assert_eq!(buffer.read_u16().unwrap(), 1); // Class
        assert_eq!(buffer.read_u32().unwrap(), 3600); // TTL
        let data_len = buffer.read_u16().unwrap();
        assert!(data_len > 0); // Ensure data length is set correctly
        assert_eq!(buffer.read_u16().unwrap(), 10); // Preference
        let mut exchange = String::new();
        buffer.read_qname(&mut exchange).unwrap();
        assert_eq!(exchange, "mx.example.com");
    }

    #[test]
    fn test_write_aaaa_record() {
        let record = DnsRecord::AAAA {
            domain: "example.com".to_string(),
            addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            ttl: 3600,
        };
        let mut buffer = ByteBuffer::new();
        record.write(&mut buffer);

        buffer.seek(0).unwrap();
        let mut domain = String::new();
        buffer.read_qname(&mut domain).unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(buffer.read_u16().unwrap(), 28); // QueryType::AAAA
        assert_eq!(buffer.read_u16().unwrap(), 1); // Class
        assert_eq!(buffer.read_u32().unwrap(), 3600); // TTL
        let data_len = buffer.read_u16().unwrap();
        assert_eq!(data_len, 16); // Ensure data length is set correctly
        let mut addr = [0u8; 16];
        for i in 0..16 {
            addr[i] = buffer.read().unwrap();
        }
        assert_eq!(addr, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    }
}
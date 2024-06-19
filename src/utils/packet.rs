use super::{byte_buffer::ByteBuffer, header::DnsHeader, query_type::QueryType, question::DnsQuestion, record::DnsRecord};
use std::io::Result;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, PartialEq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut ByteBuffer) -> Result<DnsPacket> {
        let mut packet = DnsPacket::new();
        packet.header.read(buffer)?;

        for _ in 0..packet.header.questions {
            let mut question = DnsQuestion::new(String::new(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            packet.questions.push(question);
        }

        for _ in 0..packet.header.answers {
            packet.answers.push(DnsRecord::read(buffer)?);
        }

        for _ in 0..packet.header.authoritative_entries {
            packet.authorities.push(DnsRecord::read(buffer)?);
        }

        for _ in 0..packet.header.resource_entries {
            packet.resources.push(DnsRecord::read(buffer)?);
        }

        Ok(packet)
    }

    pub fn write(&self, buffer: &mut ByteBuffer) -> Result<()>{
        self.header.write(buffer).unwrap();

        for q in &self.questions {
            q.write(buffer);
        }

        for a in &self.answers {
            a.write(buffer);
        }

        for a in &self.authorities {
            a.write(buffer);
        }

        for a in &self.resources {
            a.write(buffer);
        }

        Ok(())
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        for a in &self.answers {
            if let DnsRecord::A { addr, .. } = a {
                return Some(*addr);
            }
        }
        None
    }

    pub fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities.iter().filter_map(|record| match record {
            DnsRecord::NS { domain, ns, ..} => Some((domain.as_str(), ns.as_str())),
            _ => None,
        }).filter(move |(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname).flat_map(|(_, ns)| {
            self.resources.iter().filter_map(move |record| match record {
                DnsRecord::A { domain, addr, .. } if domain == ns => Some(addr),
                _ => None,
            }).next()
        }).map(|addr| *addr).next() // @todo: Crashes if no NS record is found
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, ns)| ns).next()
    }

    pub fn write_to_bytes(&self) -> Result<[u8; 512]> {
        let mut buffer = ByteBuffer::new();
        self.write(&mut buffer)?;
        Ok(buffer.buffer)
    }

}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::utils::byte_buffer::ByteBuffer;
    use crate::utils::header::DnsHeader;
    use crate::utils::query_type::QueryType;
    use crate::utils::question::DnsQuestion;
    use crate::utils::record::DnsRecord;

    #[test]
    fn test_new_dns_packet() {
        let packet = DnsPacket::new();
        assert_eq!(packet.header, DnsHeader::new());
        assert!(packet.questions.is_empty());
        assert!(packet.answers.is_empty());
        assert!(packet.authorities.is_empty());
        assert!(packet.resources.is_empty());
    }

    #[test]
    fn test_from_buffer() {
        let mut buffer = ByteBuffer::new();
        let header = DnsHeader::new();
        header.write(&mut buffer).unwrap();

        let question = DnsQuestion::new("example.com".to_string(), QueryType::A);
        question.write(&mut buffer);

        let answer = DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(127, 0, 0, 1),
            ttl: 3600,
        };
        answer.write(&mut buffer);

        buffer.seek(0).unwrap();

        let mut packet = DnsPacket::new();
        packet.header = header;
        packet.header.questions = 1;
        packet.header.answers = 1;
        packet.questions.push(question);
        packet.answers.push(answer);

        let deserialized_packet = DnsPacket::from_buffer(&mut buffer).unwrap();
        for (i, q) in deserialized_packet.questions.iter().enumerate() {
            assert_eq!(q, &packet.questions[i]);
        }
        for (i, a) in deserialized_packet.answers.iter().enumerate() {
            assert_eq!(a, &packet.answers[i]);
        }
    }

    #[test]
    fn test_write_dns_packet() {
        let mut buffer = ByteBuffer::new();
        
        let mut packet = DnsPacket::new();
        packet.header.questions = 1;
        packet.header.answers = 1;

        let question = DnsQuestion::new("example.com".to_string(), QueryType::A);
        packet.questions.push(question.clone());

        let answer = DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(127, 0, 0, 1),
            ttl: 3600,
        };
        packet.answers.push(answer.clone());

        packet.write(&mut buffer).unwrap();

        buffer.seek(0).unwrap();

        let deserialized_packet = DnsPacket::from_buffer(&mut buffer).unwrap();
        assert_eq!(deserialized_packet.header.questions, packet.header.questions);
        assert_eq!(deserialized_packet.header.answers, packet.header.answers);
        assert_eq!(deserialized_packet.questions, packet.questions);
        assert_eq!(deserialized_packet.answers, packet.answers);
    }
}

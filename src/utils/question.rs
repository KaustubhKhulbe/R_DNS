use super::{byte_buffer::ByteBuffer, query_type::QueryType};
use std::io::Result;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }

    pub fn read(&mut self, buffer: &mut ByteBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        let t = buffer.read_u16()?;
        self.qtype = QueryType::from_num(t);
        let _ = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut ByteBuffer) {
        let _ = buffer.write_qname(&self.name);
        let _ = buffer.write_u16(self.qtype.to_num());
        let _ = buffer.write_u16(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::byte_buffer::ByteBuffer;
    use crate::utils::query_type::QueryType;

    #[test]
    fn test_new_dns_question() {
        let name = "example.com".to_string();
        let qtype = QueryType::A;
        let question = DnsQuestion::new(name.clone(), qtype);

        assert_eq!(question.name, name);
        assert_eq!(question.qtype, qtype);
    }

    #[test]
    fn test_read_dns_question() {
        let mut buffer = ByteBuffer::new();
        buffer.write_qname("example.com").unwrap();
        buffer.write_u16(QueryType::A.to_num()).unwrap();
        buffer.write_u16(1).unwrap();
        buffer.seek(0).unwrap();

        let mut question = DnsQuestion::new(String::new(), QueryType::UNKNOWN(0));
        question.read(&mut buffer).unwrap();

        assert_eq!(question.name, "example.com");
        assert_eq!(question.qtype, QueryType::A);
    }

    #[test]
    fn test_write_dns_question() {
        let question = DnsQuestion::new("example.com".to_string(), QueryType::A);
        let mut buffer = ByteBuffer::new();
        question.write(&mut buffer);

        buffer.seek(0).unwrap();
        let mut name = String::new();
        buffer.read_qname(&mut name).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(buffer.read_u16().unwrap(), QueryType::A.to_num());
        assert_eq!(buffer.read_u16().unwrap(), 1);
    }
}

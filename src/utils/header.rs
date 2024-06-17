use super::{byte_buffer::ByteBuffer, result_code::ResultCode};
use std::io::Result;

/**
ID -- Packet Identifier -- 16 bits
QR -- Query Response -- 1 bit
OPCODE -- Operation Code -- 4 bits
AA -- Authoritative Answer -- 1 bit
TC -- Truncated Message -- 1 bit
RD -- Recursion Desired -- 1 bit
RA -- Recursion Available -- 1 bit
Z -- Reserved -- 3 bits (Split into Z, response, and authed_data)
RCODE -- Response Code -- 4 bits
QDCOUNT -- Question Count -- 16 bits
ANCOUNT -- Answer Count -- 16 bits
NSCOUNT -- Authority Count -- 16 bits
ARCOUNT -- Additional Count -- 16 bits
*/
#[derive(Clone, Debug, PartialEq)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut ByteBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut ByteBuffer) -> Result<()>{
        let _ = buffer.write_u16(self.id);

        let mut a = 0u8;
        if self.recursion_desired {
            a |= 1 << 0;
        }
        if self.truncated_message {
            a |= 1 << 1;
        }
        if self.authoritative_answer {
            a |= 1 << 2;
        }
        a |= self.opcode << 3;
        if self.response {
            a |= 1 << 7;
        }

        let mut b = self.rescode as u8;
        if self.checking_disabled {
            b |= 1 << 4;
        }
        if self.authed_data {
            b |= 1 << 5;
        }
        if self.z {
            b |= 1 << 6;
        }
        if self.recursion_available {
            b |= 1 << 7;
        }

        let _ = buffer.write_u16((a as u16) << 8 | b as u16);
        let _ = buffer.write_u16(self.questions);
        let _ = buffer.write_u16(self.answers);
        let _ = buffer.write_u16(self.authoritative_entries);
        let _ = buffer.write_u16(self.resource_entries);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write_header() {
        let mut header = DnsHeader::new();
        header.id = 6666;
        header.recursion_desired = true;
        header.questions = 1;

        let mut buffer = ByteBuffer::new();
        header.write(&mut buffer).unwrap();

        let mut read_header = DnsHeader::new();
        buffer.seek(0).unwrap();
        read_header.read(&mut buffer).unwrap();

        assert_eq!(header.id, read_header.id);
        assert_eq!(header.recursion_desired, read_header.recursion_desired);
        assert_eq!(header.questions, read_header.questions);
    }
}
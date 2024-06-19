use std::io::{Result, Error};
pub struct ByteBuffer {
    pub buffer: [u8; 512],
    pub position: usize,
}

impl ByteBuffer {
    pub fn new() -> Self {
        Self {
            buffer: [0; 512],
            position: 0,
        }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn step(&mut self, steps: usize) -> Result<()>{
        self.position += steps;

        Ok(())
    }

    pub fn seek(&mut self, position: usize) -> Result<()> {
        self.position = position;

        Ok(())
    }

    pub fn read(&mut self) -> Result<u8> {
        if self.position >= 512 {
            return Err(Error::new(std::io::ErrorKind::Other, "Buffer overflow"));
        }

        let res = self.buffer[self.position];
        self.step(1)?;
        Ok(res)
    }

    pub fn get(&self, position: usize) -> Result<u8> {
        if position >= 512 {
            return Err(Error::new(std::io::ErrorKind::Other, "Buffer overflow"));
        }

        Ok(self.buffer[position])
    }

    pub fn get_range_(&self, start: usize, end: usize) -> Result<&[u8]> {
        if start >= 512 || end >= 512 {
            return Err(Error::new(std::io::ErrorKind::Other, "Buffer overflow"));
        }

        Ok(&self.buffer[start..end])
    }

    pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        Ok(self.get_range_(start, start+len)?)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
        | ((self.read()? as u32) << 16)
        | ((self.read()? as u32) << 8)
        | ((self.read()? as u32) << 0);
        Ok(res)
    }

    pub fn read_qname(&mut self, out : &mut String) -> Result<()> {
        let mut position = self.position;
        let mut jump = false;
        let max_jumps = 5;
        let mut jumps = 0;
        let mut delim = "";
    
        loop {
            let len = self.get(position)?;
            if jumps > max_jumps {
                return Err(Error::new(std::io::ErrorKind::Other, format!("Limit of {} jumps exceeded", max_jumps)));
            }

            if len & 0xC0 == 0xC0 {
                if !jump {
                    self.seek(position + 2)?;
                }

                let new_jump = ((len as u16) ^ 0xC0) << 8 | self.get(position+1)? as u16;
                let offset = new_jump as usize;
                position = offset;

                jump = true;
                jumps += 1;
            } else {
                position += 1;
                if len == 0 {
                    break;
                }
                out.push_str(delim);
                out.push_str(&String::from_utf8_lossy(self.get_range(position, len as usize)?).to_lowercase());
                delim = ".";
                position += len as usize;
            }
        };

        if !jump {
            self.seek(position)?;
        }

        Ok(())
    }

    pub fn write(&mut self, val: u8) -> Result<()> {
        if self.position >= 512 {
            return Err(Error::new(std::io::ErrorKind::Other, "Buffer overflow"));
        }

        self.buffer[self.position] = val;
        self.step(1)?;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?; // & 0xFF extracts the last 8 bits
        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        for part in qname.split(".") {
            self.write_u8(part.len() as u8)?;
            for c in part.chars() {
                self.write_u8(c as u8)?;
            }
        }
        self.write_u8(0)?;
        Ok(())
    }

    pub fn set(&mut self, position: usize, val: u8) -> Result<()> {
        if position >= 512 {
            return Err(Error::new(std::io::ErrorKind::Other, "Buffer overflow"));
        }

        self.buffer[position] = val;
        Ok(())
    }

    pub fn set_u16(&mut self, position: usize, val: u16) -> Result<()> {
        self.set(position, (val >> 8) as u8)?;
        self.set(position+1, (val & 0xFF) as u8)?;
        Ok(())
    }

    pub fn from_buffer(buffer: &[u8]) -> Self {
        let mut new_buffer = ByteBuffer::new();
        for (i, &val) in buffer.iter().enumerate() {
            new_buffer.set(i, val).unwrap();
        }
        new_buffer.seek(0).unwrap();
        new_buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_byte_buffer() {
        let buffer = ByteBuffer::new();
        assert_eq!(buffer.position, 0);
        assert_eq!(buffer.buffer, [0; 512]);
    }

    #[test]
    fn test_step() {
        let mut buffer = ByteBuffer::new();
        buffer.step(5).unwrap();
        assert_eq!(buffer.position, 5);
    }

    #[test]
    fn test_seek() {
        let mut buffer = ByteBuffer::new();
        buffer.seek(10).unwrap();
        assert_eq!(buffer.position, 10);
    }

    #[test]
    fn test_read_write() {
        let mut buffer = ByteBuffer::new();
        buffer.write(42).unwrap();
        buffer.seek(0).unwrap();
        assert_eq!(buffer.read().unwrap(), 42);
    }

    #[test]
    fn test_get() {
        let mut buffer = ByteBuffer::new();
        buffer.write(42).unwrap();
        assert_eq!(buffer.get(0).unwrap(), 42);
    }

    #[test]
    fn test_get_range() {
        let mut buffer = ByteBuffer::new();
        buffer.write(42).unwrap();
        buffer.write(43).unwrap();
        assert_eq!(buffer.get_range(0, 2).unwrap(), &[42, 43]);
    }

    #[test]
    fn test_read_u16() {
        let mut buffer = ByteBuffer::new();
        buffer.write_u16(0x1234).unwrap();
        buffer.seek(0).unwrap();
        assert_eq!(buffer.read_u16().unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u32() {
        let mut buffer = ByteBuffer::new();
        buffer.write_u32(0x12345678).unwrap();
        buffer.seek(0).unwrap();
        assert_eq!(buffer.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_qname() {
        let mut buffer = ByteBuffer::new();
        buffer.write_qname("example.com").unwrap();
        buffer.seek(0).unwrap();
        let mut qname = String::new();
        buffer.read_qname(&mut qname).unwrap();
        assert_eq!(qname, "example.com");
    }

    #[test]
    fn test_write_u8() {
        let mut buffer = ByteBuffer::new();
        buffer.write_u8(0x12).unwrap();
        buffer.seek(0).unwrap();
        assert_eq!(buffer.read().unwrap(), 0x12);
    }

    #[test]
    fn test_write_u16() {
        let mut buffer = ByteBuffer::new();
        buffer.write_u16(0x1234).unwrap();
        buffer.seek(0).unwrap();
        assert_eq!(buffer.read_u16().unwrap(), 0x1234);
    }

    #[test]
    fn test_write_u32() {
        let mut buffer = ByteBuffer::new();
        buffer.write_u32(0x12345678).unwrap();
        buffer.seek(0).unwrap();
        assert_eq!(buffer.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_write_qname() {
        let mut buffer = ByteBuffer::new();
        buffer.write_qname("example.com").unwrap();
        buffer.seek(0).unwrap();
        let mut qname = String::new();
        buffer.read_qname(&mut qname).unwrap();
        assert_eq!(qname, "example.com");
    }

    #[test]
    fn test_set() {
        let mut buffer = ByteBuffer::new();
        buffer.set(0, 42).unwrap();
        assert_eq!(buffer.get(0).unwrap(), 42);
    }

    #[test]
    fn test_set_u16() {
        let mut buffer = ByteBuffer::new();
        buffer.set_u16(0, 0x1234).unwrap();
        assert_eq!(buffer.read_u16().unwrap(), 0x1234);
    }
}

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    // new, zero-initialized byte packet
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }
    
    // pos will get the current position of the bytepacket
    pub fn pos(&self) -> usize {
        self.pos
    }

    // modifies the reference by pushing the buffer
    // position forward a certain no. of steps
    pub fn step(&mut self, steps: usize) -> super::Result<()> {
        self.pos += steps;
        Ok(())
    }

        /// Change the buffer position
        pub fn seek(&mut self, pos: usize) -> super::Result<()> {
            self.pos = pos;
    
            Ok(())
        }



    // read will read a single byte and push the buffer
    // position one step forward
    pub fn read(&mut self) -> super::Result<u8> {
        if self.pos >= 512 {
            // todo: research the .into syntax
            return Err("end of buffer".into());
        }

        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    // get a single byte, without changing the position of the buffer
    pub fn get(&mut self, pos: usize) -> super::Result<u8> {
        if pos >= 512 {
            return Err("end of buffer".into());
        }
        Ok(self.buf[pos])
    }

    // get_range will yield a range of bytes from a starting position
    pub fn get_range(&mut self, start: usize, len: usize) -> super::Result<&[u8]> {
        if start + len >= 512 {
            return Err("end of buffer".into())
        }
        Ok(&self.buf[start..start + len as usize])
    }

    // read_u16 will read 2 bytes and step forward 2 steps
    pub fn read_u16(&mut self) -> super::Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    // read_u32 will read 2 bytes and step forward 2 steps
    pub fn read_u32(&mut self) -> super::Result<u32> {
        let res = ((self.read()? as u32) << 24) 
                    | ((self.read()? as u32) << 16)
                    | ((self.read()? as u32) << 8)
                    | ((self.read()? as u32) << 0);

        Ok(res)
    }

    // let's read in a query name
    pub fn read_qname(&mut self, outstr: &mut String) -> super::Result<()> {
        let mut pos = self.pos();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";

        loop {
            if jumps_performed > max_jumps {
                return Err(format!("limit of {} jumps exceeded", max_jumps).into());
            }

            let len = self.get(pos)?;

            // load the next byte into memory. We want to see if message
            // compression is being used, so we need to check if the 2 MSBs are 
            // set to 1. 
            // len = 1 byte
            // 0xC0 = 1 byte which is 0b11000000 in binary
            // logical AND proves that the 2 MSBs are set to 11, which means
            // we need to follow the jump
            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2);
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            }

            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    pub fn write(&mut self, val: u8) -> super::Result<()> {
        if self.pos >= 512 {
            return Err("end of buffer".into())
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> super::Result<()> {
        self.write(val)?;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> super::Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> super::Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> super::Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }

}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: super::header::DnsHeader,
    pub questions: Vec<super::question::DnsQuestion>,
    pub answers: Vec<super::record::DnsRecord>,
    pub authorities: Vec<super::record::DnsRecord>,
    pub resources: Vec<super::record::DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: super::header::DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> super::Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = super::question::DnsQuestion::new("".to_string(), super::query::QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = super::record::DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = super::record::DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = super::record::DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> super::Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }
}
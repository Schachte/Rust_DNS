use super::{result::ResultCode, packet::BytePacketBuffer};

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: super::result::ResultCode,       // 4 bits
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

            rescode: super::result::ResultCode::NOERROR,
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

    // read wants to take a BytePacketBuffer and deserialize it into this DnsHeader.
    // this allows us to make sense of the incoming TCP byte stream
    /*
     
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

     */
    pub fn read(&mut self, buffer: &mut super::packet::BytePacketBuffer) -> super::Result<()> {
        // We know the header structure, so the bit twiddling should be of no surprise, but
        // I'll add comments for clarity

        // the first 16 bits are the random ID specified in the RFC
        self.id = buffer.read_u16()?;

        // the remaining 16 bits are the flags, we can get clever for parsing them
        let flags = buffer.read_u16()?;

        // Let's load them in 2 chunks. 
        // this confused me at first, but I misread the ASCII diagram. The MSB is starting at Z -> 
        // RCODE -> QR... with that said:

        // flags is 16 bits, if we right shift 8 bits, we throw away RA, Z and RCode
        let a = (flags >> 8) as u8;

        // b is just taking the first 8 bits (RA, Z RCODE)
        let b = (flags & 0xFF) as u8;

        // the << 0 is for reading clarity, but equivalent to a AND 1
        // basically we want to eval the flag bits to see if they're flipped off or on
        // remember, the AA, TC, RD flags are the current LSBs
        
        // imagine we have AA TC and RD being 1, 1, 0
        // so basically this focuses on the LSB and nothing else
        // 10110110 <-- RD
        // 00000001

        // RD: see above -> output = 0
        self.recursion_desired = (a & (1 << 0)) > 0;

        // 10110110 <-- RD
        // 00000010
        // using above picture, this shift 1 over so we have 2 in binary (10)
        // IE TC is 1
        self.truncated_message = (a & (1 << 1)) > 0;

        // 10110110 <-- RD
        // 00000100
        // using above picture, this shift 1 over so we have 4 in binary (100)
        // IE AA is 1
        self.authoritative_answer = (a & (1 << 2)) > 0;

        // opcode is interesting. We know we have the 8 bits as LSB, but we want to focus on the 4
        // bits of the opcode. well.. AA, TC and RD are only 3 bits, so just discard them with 
        // a 3 bit right shift. 0x0F is Hex for 0b1111
        // we set the AND RHS to 0x0F because we can light up which bit is flipped for the opcode
        self.opcode = (a >> 3) & 0x0F;

        // response is easy because we reach wayyyy over the MSB of the.. well current LSB 8 bits
        // this is a single bit and the total current buffer is 8 bits, so discard the 7 LSB bits
        // and AND with 1
        self.response = (a & (1 << 7)) > 0;

        // nice little fuckery to AND hex to generate int
        self.rescode = ResultCode::from_num(b & 0x0F);


        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;

        // just needs to be greater than 0
        self.z = (b & (1 << 6)) > 0;

        // 1000_0000
        // discard 7 bits to focus on RA
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }


    pub fn write(&self, buffer: &mut BytePacketBuffer) -> super::Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}
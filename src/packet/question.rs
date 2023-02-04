#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: super::query::QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: super::query::QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }

    pub fn read(&mut self, buffer: &mut super::packet::BytePacketBuffer) -> super::Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = super::query::QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;
        Ok(())
    }

    pub fn write(&self, buffer: &mut super::packet::BytePacketBuffer) -> super::Result<()> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

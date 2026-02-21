use byteorder::{ByteOrder, LittleEndian};

#[derive(Debug)]
pub struct MftRecordHeader {
    pub signature: String, // "FILE" или "BAAD"
    pub update_sequence_offset: u16,
    pub update_sequence_size: u16,
    pub logfile_sequence_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub first_attribute_offset: u16,
    pub flags: u16, // 0x01 = InUse, 0x02 = Directory
    pub real_size: u32,
    pub allocated_size: u32,
    pub base_record_reference: u64,
}

impl MftRecordHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 48 { return None; }
        
        let sig = String::from_utf8_lossy(&data[0..4]).into_owned();
        if sig != "FILE" && sig != "BAAD" {
            return None; // Пропускаем мусор
        }

        Some(Self {
            signature: sig,
            update_sequence_offset: LittleEndian::read_u16(&data[4..6]),
            update_sequence_size: LittleEndian::read_u16(&data[6..8]),
            logfile_sequence_number: LittleEndian::read_u64(&data[8..16]),
            sequence_number: LittleEndian::read_u16(&data[16..18]),
            hard_link_count: LittleEndian::read_u16(&data[18..20]),
            first_attribute_offset: LittleEndian::read_u16(&data[20..22]),
            flags: LittleEndian::read_u16(&data[22..24]),
            real_size: LittleEndian::read_u32(&data[24..28]),
            allocated_size: LittleEndian::read_u32(&data[28..32]),
            base_record_reference: LittleEndian::read_u64(&data[32..40]),
        })
    }
    
    pub fn is_in_use(&self) -> bool {
        self.flags & 0x01 != 0
    }
    
    pub fn is_directory(&self) -> bool {
        self.flags & 0x02 != 0
    }
}
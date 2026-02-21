use byteorder::{ByteOrder, LittleEndian};
use chrono::{DateTime, Utc};
use super::utils::filetime_to_datetime;

#[derive(Debug)]
pub struct StandardInformation {
    pub creation_time: DateTime<Utc>,
    pub modified_time: DateTime<Utc>,
    pub mft_modified_time: DateTime<Utc>,
    pub accessed_time: DateTime<Utc>,
    pub file_attributes: u32, 
    pub security_id: u32,
}

impl StandardInformation {
    pub fn parse(data: &[u8]) -> Option<Self> {
        // ИЗМЕНЕНИЕ 2: Снижаем минимальный порог до 48 байт (стандарт Windows NT/2000)
        if data.len() < 48 { return None; }
        
        // Флаги (DOS attributes) начинаются со смещения 32, размер 4 байта
        let file_attributes = if data.len() >= 36 {
            LittleEndian::read_u32(&data[32..36])
        } else {
            0
        };

        // Security ID начинается со смещения 52, размер 4 байта
        let security_id = if data.len() >= 56 {
            LittleEndian::read_u32(&data[52..56])
        } else {
            0
        };

        Some(Self {
            creation_time: filetime_to_datetime(LittleEndian::read_u64(&data[0..8])),
            modified_time: filetime_to_datetime(LittleEndian::read_u64(&data[8..16])),
            mft_modified_time: filetime_to_datetime(LittleEndian::read_u64(&data[16..24])),
            accessed_time: filetime_to_datetime(LittleEndian::read_u64(&data[24..32])),
            file_attributes,
            security_id,
        })
    }
}

#[derive(Debug)]
pub struct FileNameAttribute {
    pub parent_directory_reference: u64,
    pub creation_time: DateTime<Utc>,
    pub modified_time: DateTime<Utc>,
    pub mft_modified_time: DateTime<Utc>,
    pub accessed_time: DateTime<Utc>,
    pub logical_size: u64,
    pub name_type: u8,
    pub name: String,
}

impl FileNameAttribute {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 66 { return None; } 
        
        let name_length = data[64] as usize;
        let name_type = data[65];
        let name_offset = 66;
        let name_bytes_len = name_length * 2;
        if data.len() < name_offset + name_bytes_len { return None; }
        
        let name_u16: Vec<u16> = data[name_offset..name_offset + name_bytes_len]
            .chunks_exact(2)
            .map(|chunk| LittleEndian::read_u16(chunk))
            .collect();
            
        let name = String::from_utf16_lossy(&name_u16);

        Some(Self {
            parent_directory_reference: LittleEndian::read_u64(&data[0..8]),
            creation_time: filetime_to_datetime(LittleEndian::read_u64(&data[8..16])),
            modified_time: filetime_to_datetime(LittleEndian::read_u64(&data[16..24])),
            mft_modified_time: filetime_to_datetime(LittleEndian::read_u64(&data[24..32])),
            accessed_time: filetime_to_datetime(LittleEndian::read_u64(&data[32..40])),
            logical_size: LittleEndian::read_u64(&data[48..56]),
            name_type,
            name,
        })
    }
}
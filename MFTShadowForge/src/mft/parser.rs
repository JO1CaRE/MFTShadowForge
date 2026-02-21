use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom, Read};

use super::path_builder::PathBuilder;
use super::record::MftRecordHeader;

#[derive(Debug, PartialEq)]
pub enum FixupResult {
    Ok,
    TornWrite,
    Failed,
}

pub fn apply_fixups(data: &mut [u8], header: &MftRecordHeader, bytes_per_sector: u16) -> FixupResult {
    let bytes_per_sector = bytes_per_sector as usize;
    if bytes_per_sector == 0 || data.len() % bytes_per_sector != 0 { return FixupResult::Failed; }
    let usa_offset = header.update_sequence_offset as usize;
    let usa_count = header.update_sequence_size as usize;
    if usa_count < 2 || usa_offset + usa_count * 2 > data.len() { return FixupResult::Failed; }
    
    let usn_0 = data[usa_offset];
    let usn_1 = data[usa_offset + 1];
    let sectors_in_record = data.len() / bytes_per_sector;
    let max_fixups = std::cmp::min(usa_count.saturating_sub(1), sectors_in_record);
    let mut torn_write = false;

    for i in 1..=max_fixups {
        let sector_end = i * bytes_per_sector;
        if sector_end < 2 || sector_end > data.len() { return FixupResult::Failed; }
        let sector_tail = sector_end - 2;

        if data[sector_tail] != usn_0 || data[sector_tail + 1] != usn_1 { torn_write = true; }

        let fixup_off = usa_offset + i * 2;
        if fixup_off + 1 >= data.len() { return FixupResult::Failed; }

        data[sector_tail] = data[fixup_off];
        data[sector_tail + 1] = data[fixup_off + 1];
    }
    if torn_write { FixupResult::TornWrite } else { FixupResult::Ok }
}

pub struct MftParser {
    pub reader: BufReader<File>,
    pub path_builder: PathBuilder,
    pub file_size: u64,
    pub record_size: usize,
    pub bytes_per_sector: u16,
}

impl MftParser {
    pub fn new(path: &str, record_size: usize, bytes_per_sector: u16) -> Result<Self, std::io::Error> {
        let file = File::open(path)?;
        let file_size = file.metadata()?.len();
        Ok(Self {
            reader: BufReader::new(file),
            path_builder: PathBuilder::new(),
            file_size, record_size, bytes_per_sector,
        })
    }

    pub fn total_records(&self) -> u64 {
        if self.record_size == 0 { return 0; }
        self.file_size / self.record_size as u64
    }

    pub fn get_update_sequence_number(record: &[u8], header: &MftRecordHeader) -> Option<u16> {
        let usa_offset = header.update_sequence_offset as usize;
        if usa_offset + 2 <= record.len() {
            Some(u16::from_le_bytes([record[usa_offset], record[usa_offset + 1]]))
        } else { None }
    }


    pub fn fetch_record(&mut self, entry_num: u64) -> Option<Vec<u8>> {
        let offset = entry_num * self.record_size as u64;
        if offset >= self.file_size { return None; }
        let mut buf = vec![0u8; self.record_size];
        
        let current_pos = self.reader.stream_position().ok()?;
        self.reader.seek(SeekFrom::Start(offset)).ok()?;
        self.reader.read_exact(&mut buf).ok()?;
        self.reader.seek(SeekFrom::Start(current_pos)).ok()?;
        
        Some(buf)
    }
}
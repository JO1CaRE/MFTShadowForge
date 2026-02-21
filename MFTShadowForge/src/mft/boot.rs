use byteorder::{ByteOrder, LittleEndian};

#[derive(Debug, Clone)]
pub struct NtfsBootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub mft_lcn: u64,
    pub mft_mirror_lcn: u64,
    pub clusters_per_file_record_segment: i8,
    pub clusters_per_index_buffer: i8,
    pub volume_serial_number: u64,
}

impl NtfsBootSector {
    pub fn parse(vbr: &[u8]) -> Option<Self> {
        if vbr.len() < 512 {
            return None;
        }

        let oem = &vbr[3..11];
        if oem != b"NTFS    " {
            return None;
        }

        let bytes_per_sector = LittleEndian::read_u16(&vbr[11..13]);
        let sectors_per_cluster = vbr[13];

        let mft_lcn = LittleEndian::read_u64(&vbr[48..56]);
        let mft_mirror_lcn = LittleEndian::read_u64(&vbr[56..64]);

        let clusters_per_file_record_segment = vbr[64] as i8;
        let clusters_per_index_buffer = vbr[68] as i8;
        let volume_serial_number = LittleEndian::read_u64(&vbr[72..80]);

        Some(Self {
            bytes_per_sector,
            sectors_per_cluster,
            mft_lcn,
            mft_mirror_lcn,
            clusters_per_file_record_segment,
            clusters_per_index_buffer,
            volume_serial_number,
        })
    }

    pub fn bytes_per_cluster(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    pub fn file_record_size_bytes(&self) -> Option<u32> {
        let bpc = self.bytes_per_cluster() as u32;
        let v = self.clusters_per_file_record_segment;
        if v == 0 {
            return None;
        }

        if v > 0 {
            Some(bpc.saturating_mul(v as u32))
        } else {
            let pow = (-v) as u32;
            if pow > 31 {
                None
            } else {
                Some(1u32 << pow)
            }
        }
    }
}
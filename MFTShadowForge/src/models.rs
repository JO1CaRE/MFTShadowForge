use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MftEntry {
    pub entry_number: u64,
    pub sequence_number: u16,

    pub parent_entry_number: u64,
    pub parent_sequence_number: u16,

    pub in_use: bool,
    pub is_directory: bool,

    pub parent_path: String,
    pub file_name: String,
    pub extension: Option<String>,

    #[serde(rename = "Full_Path")]
    pub full_path: String,

    pub has_ads: bool,
    pub is_ads: bool,

    pub file_size: u64,

    pub created0x10: Option<String>,
    pub created0x30: Option<String>,
    pub last_modified0x10: Option<String>,
    pub last_modified0x30: Option<String>,
    pub last_record_change0x10: Option<String>,
    pub last_record_change0x30: Option<String>,
    pub last_access0x10: Option<String>,
    pub last_access0x30: Option<String>,

    pub update_sequence_number: u64,
    pub logfile_sequence_number: u64,

    pub security_id: u32,
    pub si_flags: u32,

    pub reference_count: u16,
    pub name_type: u8,

    pub timestomped: bool,
    pub fits_rules: bool,

    pub zone_id_contents: Option<String>,
    pub content_data: Option<String>,

    #[serde(rename = "uSecZeros")]
    pub u_sec_zeros: bool,
    pub copied: bool,
    
    pub torn_write: bool,
    
    // ИЗМЕНЕНИЕ 3: Флаг для non-resident $ATTRIBUTE_LIST
    pub complex_extents: bool,

    pub fn_attribute_id: u16,
    pub other_attribute_id: u16,

    pub source_file: String,

    pub signature: String,
    pub base_record_reference: u64,
    pub real_size: u32,
    pub allocated_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftMeta {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub bytes_per_cluster: u64,
    pub mft_lcn: u64,
    pub mft_mirror_lcn: u64,              
    pub clusters_per_index_buffer: i8,     
    pub mft_record_size: u32,
    pub volume_serial_number: u64,
    pub source: String,
}
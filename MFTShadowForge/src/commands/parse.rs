use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom};
use byteorder::{ByteOrder, LittleEndian};

use crate::mft::attributes::{FileNameAttribute, StandardInformation};
use crate::mft::parser::{apply_fixups, FixupResult, MftParser};
use crate::mft::record::MftRecordHeader;
use crate::models::{MftEntry, MftMeta};
use crate::output::JsonlWriter;
use crate::rules::rules::Rule;
use crate::rules::timestamp::TimestampData;

fn meta_path_for_mft(mft_path: &str) -> String { format!("{}.meta.json", mft_path) }

fn load_mft_meta(mft_path: &str) -> Option<MftMeta> {
    serde_json::from_reader(File::open(&meta_path_for_mft(mft_path)).ok()?).ok()
}

fn read_attr_name(record: &[u8], attr_offset: usize, attr_end: usize) -> String {
    if attr_offset + 12 > attr_end { return String::new(); }
    let name_len = record[attr_offset + 9] as usize;
    let name_off = LittleEndian::read_u16(&record[attr_offset + 10..attr_offset + 12]) as usize;
    if name_len == 0 { return String::new(); }
    let name_start = attr_offset.saturating_add(name_off);
    let name_end = name_start.saturating_add(name_len * 2);
    if name_end > attr_end { return String::new(); }

    let name_bytes = &record[name_start..name_end];
    let mut u16s = Vec::with_capacity(name_len);
    for c in name_bytes.chunks_exact(2) { u16s.push(LittleEndian::read_u16(c)); }
    String::from_utf16_lossy(&u16s)
}

fn read_nonresident_data_size(record: &[u8], attr_offset: usize, attr_end: usize) -> Option<u64> {
    if attr_offset + 0x38 > attr_end { return None; }
    Some(LittleEndian::read_u64(&record[attr_offset + 0x30..attr_offset + 0x38]))
}

fn extract_human_readable(data: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(data);
    lossy.chars()
        .filter(|c| (!c.is_control() || *c == '\n' || *c == '\t' || *c == '\r') && *c != '\u{FFFD}')
        .collect()
}

// возвращаем не только буферы, но и флаг наличия non-resident $ATTRIBUTE_LIST
fn gather_record_buffers(parser: &mut MftParser, entry_num: u64, base_buffer: Vec<u8>) -> (Vec<Vec<u8>>, bool) {
    let mut buffers = vec![base_buffer];
    let mut extents_to_fetch = std::collections::HashSet::new();
    let mut complex_extents = false;

    let header = match MftRecordHeader::parse(&buffers[0]) {
        Some(h) => h,
        None => return (buffers, complex_extents),
    };

    let mut attr_offset = header.first_attribute_offset as usize;
    
    // ИЗМЕНЕНИЕ 1: Строгое ограничение по real_size (защита от мусора в slack-пространстве)
    let mut used_end = std::cmp::min(header.real_size as usize, parser.record_size);
    if used_end < attr_offset { used_end = parser.record_size; } // Защита от битого real_size

    while attr_offset + 8 <= used_end {
        let attr_type = LittleEndian::read_u32(&buffers[0][attr_offset..attr_offset + 4]);
        if attr_type == 0xFFFFFFFF || attr_type == 0 { break; }
        let attr_len = LittleEndian::read_u32(&buffers[0][attr_offset + 4..attr_offset + 8]) as usize;
        if attr_len == 0 || attr_offset.saturating_add(attr_len) > used_end { break; }

        let attr_end = attr_offset.saturating_add(attr_len);
        let non_resident = buffers[0][attr_offset + 8] != 0;

        if attr_type == 0x20 {
            if non_resident {
                complex_extents = true; // Фиксируем, что список атрибутов на диске
            } else if attr_offset + 22 <= used_end {
                let value_len = LittleEndian::read_u32(&buffers[0][attr_offset + 16..attr_offset + 20]) as usize;
                let value_off = LittleEndian::read_u16(&buffers[0][attr_offset + 20..attr_offset + 22]) as usize;
                let content_offset = attr_offset.saturating_add(value_off);
                let content_end = std::cmp::min(content_offset.saturating_add(value_len), attr_end);

                let mut list_off = content_offset;
                while list_off + 26 <= content_end {
                    let ext_type = LittleEndian::read_u32(&buffers[0][list_off..list_off + 4]);
                    if ext_type == 0 { break; }
                    let ext_len = LittleEndian::read_u16(&buffers[0][list_off + 4..list_off + 6]) as usize;
                    if ext_len == 0 || list_off.saturating_add(ext_len) > content_end { break; }

                    let base_ref = LittleEndian::read_u64(&buffers[0][list_off + 16..list_off + 24]);
                    let extent_entry = base_ref & 0xFFFFFFFFFFFF;

                    if extent_entry != entry_num && extent_entry > 0 && extent_entry < parser.total_records() {
                        extents_to_fetch.insert(extent_entry);
                    }
                    list_off += ext_len;
                }
            }
        }
        attr_offset = attr_end;
    }

    for extent_entry in extents_to_fetch {
        if let Some(mut ext_buf) = parser.fetch_record(extent_entry) {
            if let Some(eh) = MftRecordHeader::parse(&ext_buf) {
                if apply_fixups(&mut ext_buf, &eh, parser.bytes_per_sector) != FixupResult::Failed {
                    buffers.push(ext_buf);
                }
            }
        }
    }
    (buffers, complex_extents)
}

pub fn run(path: &str, out_jsonl: &str, data_flag: bool) {
    println!("[*] Запуск Parse");

    let meta_opt = load_mft_meta(path);
    let (record_size, bytes_per_sector) = meta_opt.as_ref()
        .map(|meta| (meta.mft_record_size as usize, meta.bytes_per_sector))
        .unwrap_or((1024, 512));

    let drive_prefix = meta_opt.as_ref().and_then(|m| {
        if m.source.starts_with("\\\\.\\") && m.source.len() >= 6 {
            let maybe_drive = &m.source[4..6];
            if maybe_drive.ends_with(':') { Some(maybe_drive.to_string()) } else { None }
        } else { None }
    }).unwrap_or_default(); // Если не нашли диск - будет пустая строка, пути начнутся с "\"

    let mut parser = MftParser::new(path, record_size, bytes_per_sector).unwrap();
    let total_records = parser.total_records();
    parser.path_builder.reserve(total_records as usize);

    println!("[*] Проход 1: построение дерева путей и baseline...");
    let mut record_buffer = vec![0u8; parser.record_size];
    let mut volume_birth: Option<chrono::DateTime<chrono::Utc>> = None;

    for entry_num in 0..total_records {
        if parser.reader.read_exact(&mut record_buffer).is_err() { break; }

        let header = match MftRecordHeader::parse(&record_buffer) {
            Some(h) => h, None => continue,
        };

        if header.signature == "BAAD" || header.base_record_reference != 0 { continue; } 
        if apply_fixups(&mut record_buffer, &header, parser.bytes_per_sector) == FixupResult::Failed { continue; }

        let (buffers, _) = gather_record_buffers(&mut parser, entry_num, record_buffer.clone());
        let mut best_fn: Option<FileNameAttribute> = None;

        for buf in &buffers {
            let buf_header = MftRecordHeader::parse(buf).unwrap();
            let mut attr_offset = buf_header.first_attribute_offset as usize;
            
            let mut used_end = std::cmp::min(buf_header.real_size as usize, parser.record_size);
            if used_end < attr_offset { used_end = parser.record_size; }

            while attr_offset + 8 <= used_end {
                let attr_type = LittleEndian::read_u32(&buf[attr_offset..attr_offset + 4]);
                if attr_type == 0xFFFFFFFF || attr_type == 0 { break; }
                let attr_len = LittleEndian::read_u32(&buf[attr_offset + 4..attr_offset + 8]) as usize;
                if attr_len == 0 || attr_offset.saturating_add(attr_len) > used_end { break; }

                let attr_end = attr_offset.saturating_add(attr_len);
                let non_resident = buf[attr_offset + 8] != 0;

                if attr_type == 0x10 && entry_num <= 11 && !non_resident && attr_offset + 22 <= attr_end {
                    let value_len = LittleEndian::read_u32(&buf[attr_offset + 16..attr_offset + 20]) as usize;
                    let value_off = LittleEndian::read_u16(&buf[attr_offset + 20..attr_offset + 22]) as usize;
                    let content_end = std::cmp::min(attr_offset.saturating_add(value_off).saturating_add(value_len), attr_end);
                    if let Some(slice) = buf.get(attr_offset.saturating_add(value_off)..content_end) {
                        if let Some(si) = StandardInformation::parse(slice) {
                            volume_birth = Some(volume_birth.unwrap_or(si.creation_time).min(si.creation_time));
                        }
                    }
                }

                if attr_type == 0x30 && !non_resident && attr_offset + 22 <= attr_end {
                    let value_len = LittleEndian::read_u32(&buf[attr_offset + 16..attr_offset + 20]) as usize;
                    let value_off = LittleEndian::read_u16(&buf[attr_offset + 20..attr_offset + 22]) as usize;
                    let content_end = std::cmp::min(attr_offset.saturating_add(value_off).saturating_add(value_len), attr_end);
                    if let Some(slice) = buf.get(attr_offset.saturating_add(value_off)..content_end) {
                        if let Some(fn_attr) = FileNameAttribute::parse(slice) {
                            let current_prio = match best_fn.as_ref() {
                                Some(f) if f.name_type == 1 || f.name_type == 3 => 2,
                                Some(_) => 1, None => 0,
                            };
                            if (fn_attr.name_type == 1 || fn_attr.name_type == 3) || current_prio == 0 {
                                best_fn = Some(fn_attr);
                            }
                        }
                    }
                }
                attr_offset = attr_end;
            }
        }

        if let Some(fn_attr) = best_fn {
            let parent_entry = fn_attr.parent_directory_reference & 0xFFFFFFFFFFFF;
            let parent_seq = (fn_attr.parent_directory_reference >> 48) as u16;
            parser.path_builder.add_entry(entry_num, header.sequence_number, parent_entry, parent_seq, fn_attr.name);
        }
    }

    println!("[*] Проход 2: парсинг атрибутов и экспорт в JSONL...");
    parser.reader.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = JsonlWriter::new(BufWriter::new(File::create(out_jsonl).unwrap()));

    let rules_list: Vec<Rule> = vec![
        Rule::glob(r"*\Windows\System32\AppLocker\*.txt").unwrap().and(Rule::ends_with("123.txt").not()),
        Rule::glob(r"*\Windows\IME\*.ps1").unwrap(),
        Rule::glob(r"*\$Recycle.Bin\*.exe").unwrap(),
        Rule::starts_with("C:\\Users\\Public\\").and(Rule::ends_with(".exe")),
        Rule::contains("\\system32\\").and(Rule::ends_with(".dll")),
    ];

    for entry_num in 0..total_records {
        if parser.reader.read_exact(&mut record_buffer).is_err() { break; }

        let header = match MftRecordHeader::parse(&record_buffer) {
            Some(h) => h, None => continue,
        };

        if header.signature == "BAAD" || header.base_record_reference != 0 { continue; } 

        let fixup_res = apply_fixups(&mut record_buffer, &header, parser.bytes_per_sector);
        if fixup_res == FixupResult::Failed { continue; }
        
        let is_torn_write = fixup_res == FixupResult::TornWrite;
        let (buffers, complex_extents) = gather_record_buffers(&mut parser, entry_num, record_buffer.clone());

        let mut file_name = String::new();
        let mut si_attr: Option<StandardInformation> = None;
        let mut fn_attr_data: Option<FileNameAttribute> = None;
        let mut content_data: Option<String> = None;
        let mut zone_id_contents: Option<String> = None;
        let mut has_ads = false;
        let mut data_unnamed_size: Option<u64> = None;
        let mut fn_logical_size: Option<u64> = None;

        for buf in &buffers {
            let buf_header = MftRecordHeader::parse(buf).unwrap();
            let mut attr_offset = buf_header.first_attribute_offset as usize;
            
            let mut used_end = std::cmp::min(buf_header.real_size as usize, parser.record_size);
            if used_end < attr_offset { used_end = parser.record_size; }

            while attr_offset + 8 <= used_end {
                let attr_type = LittleEndian::read_u32(&buf[attr_offset..attr_offset + 4]);
                if attr_type == 0xFFFFFFFF || attr_type == 0 { break; }

                let attr_len = LittleEndian::read_u32(&buf[attr_offset + 4..attr_offset + 8]) as usize;
                if attr_len == 0 || attr_offset.saturating_add(attr_len) > used_end { break; }

                let attr_end = attr_offset.saturating_add(attr_len);
                let non_resident = buf[attr_offset + 8] != 0;
                let attr_name = read_attr_name(&buf, attr_offset, attr_end);
                
                if attr_type == 0x80 && !attr_name.is_empty() { has_ads = true; }

                if !non_resident && attr_offset + 22 <= attr_end {
                    let value_len = LittleEndian::read_u32(&buf[attr_offset + 16..attr_offset + 20]) as usize;
                    let value_off = LittleEndian::read_u16(&buf[attr_offset + 20..attr_offset + 22]) as usize;
                    let content_end = std::cmp::min(attr_offset.saturating_add(value_off).saturating_add(value_len), attr_end);

                    match attr_type {
                        0x10 => {
                            if let Some(slice) = buf.get(attr_offset.saturating_add(value_off)..content_end) {
                                si_attr = StandardInformation::parse(slice);
                            }
                        }
                        0x30 => {
                            if let Some(slice) = buf.get(attr_offset.saturating_add(value_off)..content_end) {
                                if let Some(fn_a) = FileNameAttribute::parse(slice) {
                                    let current_prio = match fn_attr_data.as_ref() {
                                        Some(f) if f.name_type == 1 || f.name_type == 3 => 2,
                                        Some(_) => 1, None => 0,
                                    };
                                    if (fn_a.name_type == 1 || fn_a.name_type == 3) || current_prio == 0 {
                                        fn_logical_size = Some(fn_a.logical_size);
                                        file_name = fn_a.name.clone();
                                        fn_attr_data = Some(fn_a);
                                    }
                                }
                            }
                        }
                        0x80 => {
                            if attr_name.is_empty() { data_unnamed_size = Some(value_len as u64); }
                            if let Some(raw_data) = buf.get(attr_offset.saturating_add(value_off)..content_end) {
                                if attr_name == "Zone.Identifier" {
                                    zone_id_contents = Some(extract_human_readable(raw_data));
                                } else if attr_name.is_empty() && data_flag {
                                    content_data = Some(extract_human_readable(raw_data));
                                }
                            }
                        }
                        _ => {}
                    }
                } else if non_resident && attr_type == 0x80 {
                    if let Some(sz) = read_nonresident_data_size(&buf, attr_offset, attr_end) {
                        if attr_name.is_empty() { data_unnamed_size = Some(sz); }
                    }
                }
                attr_offset = attr_end;
            }
        }

        let parent_entry = fn_attr_data.as_ref().map(|f| f.parent_directory_reference & 0xFFFFFFFFFFFF).unwrap_or(0);
        let parent_seq = fn_attr_data.as_ref().map(|f| (f.parent_directory_reference >> 48) as u16).unwrap_or(0);
        
        let parent_path = parser.path_builder.get_parent_path(parent_entry, parent_seq);
        
        let full_path = if parent_path == "\\" || parent_path.is_empty() {
            format!("{}\\{}", drive_prefix, file_name)
        } else {
            let sep = if parent_path.starts_with('\\') { "" } else { "\\" };
            format!("{}{}{}\\{}", drive_prefix, sep, parent_path, file_name)
        };
        
        let mut timestomped = false;
        let mut usec_zeros = false;
        let mut copied = false;
        let mut c_0x10 = None; let mut m_0x10 = None; let mut a_0x10 = None; let mut r_0x10 = None;
        let mut c_0x30 = None; let mut m_0x30 = None; let mut a_0x30 = None; let mut r_0x30 = None;

        if let (Some(si), Some(fn_a)) = (&si_attr, &fn_attr_data) {
            let ts = TimestampData {
                si_c: si.creation_time, si_m: si.modified_time, si_e: si.mft_modified_time, si_a: si.accessed_time,
                fn_c: fn_a.creation_time, fn_m: fn_a.modified_time, fn_e: fn_a.mft_modified_time, fn_a: fn_a.accessed_time,
            };
            timestomped = ts.is_timestomped() || ts.is_before_volume_birth(volume_birth);
            usec_zeros = ts.has_usec_zeros(); copied = ts.is_copied();
            c_0x10 = Some(si.creation_time.to_rfc3339()); m_0x10 = Some(si.modified_time.to_rfc3339());
            a_0x10 = Some(si.accessed_time.to_rfc3339()); r_0x10 = Some(si.mft_modified_time.to_rfc3339());
            c_0x30 = Some(fn_a.creation_time.to_rfc3339()); m_0x30 = Some(fn_a.modified_time.to_rfc3339());
            a_0x30 = Some(fn_a.accessed_time.to_rfc3339()); r_0x30 = Some(fn_a.mft_modified_time.to_rfc3339());
        }

        let usn = MftParser::get_update_sequence_number(&record_buffer, &header).unwrap_or(0) as u64;
        let fits_rules = if !full_path.is_empty() {
            let fp_lc = full_path.to_ascii_lowercase();
            rules_list.iter().any(|r| r.check_lowered(&fp_lc))
        } else { false };

        let file_size = data_unnamed_size.or(fn_logical_size).unwrap_or(0);
        let is_dir = header.is_directory();
        let extension = if is_dir || !file_name.contains('.') { None } else { file_name.rsplit('.').next().map(|ext| ext.to_string()) };

        let entry = MftEntry {
            entry_number: entry_num, signature: header.signature.clone(), base_record_reference: header.base_record_reference,
            real_size: header.real_size, allocated_size: header.allocated_size, sequence_number: header.sequence_number,
            parent_entry_number: parent_entry, parent_sequence_number: parent_seq,
            in_use: header.is_in_use(), is_directory: is_dir, parent_path, file_name, extension, full_path,
            has_ads, is_ads: has_ads, file_size,
            created0x10: c_0x10, created0x30: c_0x30, last_modified0x10: m_0x10, last_modified0x30: m_0x30,
            last_record_change0x10: r_0x10, last_record_change0x30: r_0x30, last_access0x10: a_0x10, last_access0x30: a_0x30,
            update_sequence_number: usn, logfile_sequence_number: header.logfile_sequence_number,
            security_id: si_attr.as_ref().map(|s| s.security_id).unwrap_or(0), si_flags: si_attr.as_ref().map(|s| s.file_attributes).unwrap_or(0),
            reference_count: header.hard_link_count, name_type: fn_attr_data.as_ref().map(|f| f.name_type).unwrap_or(0),
            timestomped, fits_rules, zone_id_contents, content_data, u_sec_zeros: usec_zeros, copied,
            torn_write: is_torn_write, complex_extents, fn_attribute_id: 0, other_attribute_id: 0, source_file: path.to_string(),
        };

        let _ = writer.write(&entry);
    }
    let _ = writer.flush();
}
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use byteorder::{ByteOrder, LittleEndian};

use crate::mft::boot::NtfsBootSector;
use crate::mft::parser::{apply_fixups, FixupResult};
use crate::mft::record::MftRecordHeader;
use crate::models::MftMeta;

#[derive(Debug, Clone)]
struct DataRun {
    vcn_start: u64,
    length: u64,
    lcn: u64,
    is_sparse: bool,
}

// Вспомогательная функция для фатальных ошибок
fn fatal(msg: &str) -> ! {
    eprintln!("[!] КРИТИЧЕСКАЯ ОШИБКА: {}", msg);
    std::process::exit(1);
}

// 1. Ультра-строгие проверки границ заголовка записи
fn validate_record_boundaries(header: &MftRecordHeader, record_size: usize, is_record_0: bool) -> Result<(), String> {
    if is_record_0 && header.signature != "FILE" {
        return Err(format!("Record 0 обязан иметь сигнатуру FILE, найдено: {}", header.signature));
    }
    if !is_record_0 && header.signature != "FILE" {
        return Err(format!("Экстент обязан иметь сигнатуру FILE, найдено: {}", header.signature));
    }
    if header.real_size < 48 {
        return Err("real_size меньше минимального размера заголовка MFT (48 байт)".to_string());
    }
    if header.first_attribute_offset as usize >= record_size {
        return Err("first_attribute_offset выходит за пределы (или равен) record_size".to_string());
    }
    if header.real_size as usize > record_size {
        return Err("real_size выходит за пределы record_size".to_string());
    }
    if (header.first_attribute_offset as usize) + 8 > header.real_size as usize {
        return Err("real_size слишком мал для хранения атрибутов".to_string());
    }
    Ok(())
}

// 2. Строгая валидация VBR
fn validate_vbr(boot: &NtfsBootSector) -> Result<usize, String> {
    let bps = boot.bytes_per_sector;
    if bps != 512 && bps != 1024 && bps != 2048 && bps != 4096 {
        return Err(format!("Некорректный bytes_per_sector: {}", bps));
    }
    if boot.sectors_per_cluster == 0 || !boot.sectors_per_cluster.is_power_of_two() {
        return Err(format!("Некорректный sectors_per_cluster: {}", boot.sectors_per_cluster));
    }
    if boot.bytes_per_cluster() == 0 {
        return Err("bytes_per_cluster равен 0".to_string());
    }
    if boot.mft_lcn == 0 {
        return Err("mft_lcn равен 0".to_string());
    }
    let rs = boot.file_record_size_bytes().ok_or_else(|| "Не удалось определить file_record_size".to_string())? as usize;
    if rs < 1024 || !rs.is_power_of_two() {
        return Err(format!("Некорректный record_size: {}", rs));
    }
    Ok(rs)
}

// Жесткая проверка VBR с учетом логического сектора (размер передается явно)
fn check_vbr_strict(vol: &mut File, offset: u64, sector_size: u64) -> bool {
    let sz = sector_size as usize;
    if sz < 512 || sz > 4096 { return false; }

    let mut vbr = vec![0u8; sz];
    if vol.seek(SeekFrom::Start(offset)).is_err() || vol.read_exact(&mut vbr).is_err() {
        return false;
    }

    if &vbr[3..11] != b"NTFS    " {
        return false;
    }

    let mut valid_sig = vbr[sz - 2] == 0x55 && vbr[sz - 1] == 0xAA;
    if !valid_sig && sz > 512 {
        if vbr[510] == 0x55 && vbr[511] == 0xAA {
            valid_sig = true;
        }
    }
    if !valid_sig { return false; }

    let mut first512 = [0u8; 512];
    first512.copy_from_slice(&vbr[..512]);

    if let Some(boot) = NtfsBootSector::parse(&first512) {
        if boot.bytes_per_sector as u64 != sector_size {
            return false;
        }
        return validate_vbr(&boot).is_ok();
    }

    false
}

// Поиск NTFS партиции с поддержкой 4Kn, MBR (в т.ч. Extended) и GPT
fn find_ntfs_partition(vol: &mut File) -> Result<u64, String> {
    for &sector_size in &[512u64, 1024u64, 2048u64, 4096u64] {
        if check_vbr_strict(vol, 0, sector_size) {
            return Ok(0);
        }

        let mut sector0 = vec![0u8; sector_size as usize];
        if vol.seek(SeekFrom::Start(0)).is_err() || vol.read_exact(&mut sector0).is_err() {
            continue;
        }

        // MBR/EBR подпись всегда на 510-511
        if sector0[510] != 0x55 || sector0[511] != 0xAA {
            continue;
        }

        let mut has_gpt = false;

        // Перебор записей MBR и EBR
        for i in 0..4 {
            let offset = 446 + i * 16;
            let part_type = sector0[offset + 4];
            if part_type == 0 { continue; }
            
            if part_type == 0xEE { 
                has_gpt = true;
                break; 
            }

            let lba_start = LittleEndian::read_u32(&sector0[offset + 8 .. offset + 12]) as u64;
            let part_offset = match lba_start.checked_mul(sector_size) {
                Some(v) if v != 0 => v,
                _ => continue,
            };

            if check_vbr_strict(vol, part_offset, sector_size) { 
                return Ok(part_offset); 
            }

            // Extended Partition (цепочка EBR, включая Linux Extended 0x85)
            if part_type == 0x05 || part_type == 0x0F || part_type == 0x85 {
                let ext_base_lba = lba_start;
                let mut current_ebr_lba = ext_base_lba;
                let mut ebr_depth = 0;

                while ebr_depth < 128 { 
                    let ebr_offset = match current_ebr_lba.checked_mul(sector_size) {
                        Some(v) if v != 0 => v,
                        _ => break,
                    };
                    
                    let mut ebr_sector = vec![0u8; sector_size as usize];
                    if vol.seek(SeekFrom::Start(ebr_offset)).is_err() || vol.read_exact(&mut ebr_sector).is_err() { break; }
                    
                    // Подпись EBR всегда на 510-511
                    if ebr_sector[510] != 0x55 || ebr_sector[511] != 0xAA { break; }

                    let p1 = 446;
                    let log_type = ebr_sector[p1 + 4];
                    if log_type != 0 {
                        let log_lba_offset = LittleEndian::read_u32(&ebr_sector[p1 + 8 .. p1 + 12]) as u64;
                        let log_lba = match current_ebr_lba.checked_add(log_lba_offset) {
                            Some(v) => v,
                            None => break,
                        };
                        let log_offset = match log_lba.checked_mul(sector_size) {
                            Some(v) if v != 0 => v,
                            _ => break,
                        };
                        if check_vbr_strict(vol, log_offset, sector_size) { return Ok(log_offset); }
                    }

                    let p2 = 446 + 16;
                    let next_ebr_type = ebr_sector[p2 + 4];
                    if next_ebr_type == 0 { break; } 
                    
                    let next_ebr_lba_offset = LittleEndian::read_u32(&ebr_sector[p2 + 8 .. p2 + 12]) as u64;
                    current_ebr_lba = match ext_base_lba.checked_add(next_ebr_lba_offset) {
                        Some(v) if v != 0 => v,
                        _ => break,
                    };
                    ebr_depth += 1;
                }
            }
        }

        // Парсинг GPT
        if has_gpt {
            let gpt_header_offset = sector_size;
            let mut gpt_header = vec![0u8; sector_size as usize];
            if vol.seek(SeekFrom::Start(gpt_header_offset)).is_ok() && vol.read_exact(&mut gpt_header).is_ok() {
                if &gpt_header[0..8] == b"EFI PART" {
                    let part_entry_lba = LittleEndian::read_u64(&gpt_header[0x48..0x50]);
                    let num_entries = LittleEndian::read_u32(&gpt_header[0x50..0x54]);
                    let entry_size = LittleEndian::read_u32(&gpt_header[0x54..0x58]);

                    if entry_size >= 128 && entry_size <= 4096 && num_entries > 0 && num_entries <= 4096 {
                        if let Some(table_offset) = part_entry_lba.checked_mul(sector_size) {
                            if vol.seek(SeekFrom::Start(table_offset)).is_ok() {
                                let mut entry = vec![0u8; entry_size as usize];
                                for _ in 0..num_entries {
                                    if vol.read_exact(&mut entry).is_err() { break; }
                                    if entry[0..16].iter().all(|&b| b == 0) { continue; }

                                    let first_lba = LittleEndian::read_u64(&entry[0x20..0x28]);
                                    if let Some(part_offset) = first_lba.checked_mul(sector_size) {
                                        let cur_pos = vol.stream_position().unwrap_or(0);
                                        if check_vbr_strict(vol, part_offset, sector_size) { return Ok(part_offset); }
                                        let _ = vol.seek(SeekFrom::Start(cur_pos));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err("Подходящий NTFS раздел не найден (сканирование MBR/EBR/GPT завершено)".to_string())
}

// 3. Безопасное чтение логических байтов MFT
fn read_logical_mft(vol: &mut File, runs: &[DataRun], bpc: u64, partition_offset: u64, mut logical_offset: u64, mut buf: &mut [u8]) -> Result<(), String> {
    while !buf.is_empty() {
        let target_vcn = logical_offset / bpc;
        let offset_in_cluster = logical_offset % bpc;

        let mut found_run = None;
        for r in runs {
            let run_end = r.vcn_start.checked_add(r.length).ok_or("Переполнение при вычислении конца run")?;
            if target_vcn >= r.vcn_start && target_vcn < run_end {
                found_run = Some(r);
                break;
            }
        }
        
        let run = found_run.ok_or_else(|| format!("VCN {} не найден в базовых runs при чтении экстента", target_vcn))?;

        let to_read = std::cmp::min(buf.len() as u64, bpc - offset_in_cluster) as usize;

        if run.is_sparse {
            buf[..to_read].fill(0);
        } else {
            let physical_cluster = run.lcn.checked_add(target_vcn - run.vcn_start)
                .ok_or("Переполнение physical_cluster")?;
            let physical_offset = physical_cluster.checked_mul(bpc)
                .and_then(|po| po.checked_add(offset_in_cluster))
                .and_then(|po| po.checked_add(partition_offset))
                .ok_or("Переполнение физического смещения при чтении экстента")?;

            vol.seek(SeekFrom::Start(physical_offset)).map_err(|e| format!("Ошибка seek: {}", e))?;
            vol.read_exact(&mut buf[..to_read]).map_err(|e| format!("Ошибка read_exact: {}", e))?;
        }

        let tmp = buf;
        buf = &mut tmp[to_read..];
        logical_offset = logical_offset.checked_add(to_read as u64).ok_or("Переполнение logical_offset")?;
    }
    Ok(())
}

// 4. Строгий парсинг Data Runs
fn parse_data_runs(record: &[u8], mut run_off: usize, attr_end: usize, start_vcn: u64) -> Result<Vec<DataRun>, String> {
    let mut runs = Vec::new();
    let mut current_vcn = start_vcn;
    let mut current_lcn: i64 = 0;

    loop {
        if run_off >= attr_end { break; }
        let header = record[run_off];
        if header == 0 { break; }

        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = ((header & 0xF0) >> 4) as usize;
        run_off += 1;

        if len_bytes == 0 || len_bytes > 8 || off_bytes > 8 {
            return Err(format!("Некорректные размеры нибблов: len={}, off={}", len_bytes, off_bytes));
        }

        if run_off.checked_add(len_bytes).unwrap_or(usize::MAX).checked_add(off_bytes).unwrap_or(usize::MAX) > attr_end {
            return Err("Data runs выходят за границы атрибута".to_string());
        }

        let mut run_length: u64 = 0;
        for i in 0..len_bytes {
            run_length |= (record[run_off + i] as u64) << (i * 8);
        }
        run_off += len_bytes;

        if run_length == 0 {
            return Err("Длина Data Run равна 0".to_string());
        }

        let mut run_delta: i64 = 0;
        if off_bytes > 0 {
            for i in 0..off_bytes {
                run_delta |= (record[run_off + i] as i64) << (i * 8);
            }
            if record[run_off + off_bytes - 1] & 0x80 != 0 {
                for i in off_bytes..8 {
                    run_delta |= 0xFF_i64 << (i * 8);
                }
            }
        }
        run_off += off_bytes;

        current_lcn = current_lcn.checked_add(run_delta).ok_or("Переполнение current_lcn")?;
        
        if off_bytes > 0 && current_lcn < 0 {
            return Err(format!("Отрицательный LCN вычислен в runlist: {}", current_lcn));
        }

        let is_sparse = off_bytes == 0;
        let lcn = if is_sparse { 0 } else { current_lcn as u64 };

        runs.push(DataRun {
            vcn_start: current_vcn,
            length: run_length,
            lcn,
            is_sparse,
        });
        current_vcn = current_vcn.checked_add(run_length).ok_or("Переполнение current_vcn")?;
    }
    Ok(runs)
}

pub fn run(image: &str, out: &str) {
    println!("[*] Запуск Extract (Strict DFIR Mode)");
    println!(" -> Источник: {}", image);
    println!(" -> Выходной файл: {}", out);

    let volume_path = if image.len() <= 3 && image.starts_with(|c: char| c.is_ascii_alphabetic()) {
        format!("\\\\.\\{}", &image[0..2])
    } else {
        image.to_string()
    };

    let mut vol = match File::open(&volume_path) {
        Ok(f) => f,
        Err(e) => fatal(&format!("Ошибка открытия {}. {}", volume_path, e)),
    };

    let partition_offset = match find_ntfs_partition(&mut vol) {
        Ok(offset) => offset,
        Err(e) => fatal(&format!("Не удалось найти NTFS партицию: {}", e)),
    };

    let mut boot_sector = [0u8; 512];
    vol.seek(SeekFrom::Start(partition_offset)).unwrap_or_else(|e| fatal(&format!("Ошибка seek к VBR: {}", e)));
    vol.read_exact(&mut boot_sector).unwrap_or_else(|e| fatal(&format!("Ошибка чтения VBR: {}", e)));

    let boot = NtfsBootSector::parse(&boot_sector).unwrap_or_else(|| fatal("Не удалось распарсить VBR"));
    let record_size = match validate_vbr(&boot) {
        Ok(sz) => sz,
        Err(e) => fatal(&format!("Валидация VBR не пройдена: {}", e)),
    };

    let bytes_per_cluster = boot.bytes_per_cluster();
    let mft_physical_offset = partition_offset.checked_add(
        boot.mft_lcn.checked_mul(bytes_per_cluster).unwrap_or_else(|| fatal("Переполнение при расчете LCN MFT"))
    ).unwrap_or_else(|| fatal("Переполнение при добавлении partition offset"));

    println!("[+] Метаданные (смещение {:#X}):", partition_offset);
    println!("    bytes_per_sector: {}", boot.bytes_per_sector);
    println!("    sectors_per_cluster: {}", boot.sectors_per_cluster);
    println!("    mft_record_size: {}", record_size);

    vol.seek(SeekFrom::Start(mft_physical_offset)).unwrap_or_else(|e| fatal(&format!("Ошибка seek к $MFT: {}", e)));
    let mut mft_record0 = vec![0u8; record_size];
    vol.read_exact(&mut mft_record0).unwrap_or_else(|e| fatal(&format!("Ошибка чтения MFT record 0: {}", e)));

    let header0 = match MftRecordHeader::parse(&mft_record0) {
        Some(h) => h,
        None => fatal("MFT record 0 поврежден (заголовок не распознан)"),
    };

    if let Err(e) = validate_record_boundaries(&header0, record_size, true) {
        fatal(&format!("Отбраковка MFT record 0: {}", e));
    }

    if apply_fixups(&mut mft_record0, &header0, boot.bytes_per_sector) == FixupResult::Failed {
        fatal("Fixups MFT record 0 не применились (повреждение массива USA).");
    }

    struct ExtentTarget { start_vcn: u64, entry: u64, seq: u16 }
    let mut attr_list_entries: Vec<ExtentTarget> = Vec::new();
    let mut base_runs = Vec::new();
    let mut expected_allocated_size: u64 = 0;

    let mut attr_offset = header0.first_attribute_offset as usize;
    let used_end = header0.real_size as usize;
    let mut previous_offset = 0;

    // Парсинг Record 0
    while attr_offset + 8 <= used_end {
        if attr_offset <= previous_offset && previous_offset != 0 {
            fatal("Зацикленный атрибут (смещение перестало расти).");
        }
        previous_offset = attr_offset;

        let attr_type = LittleEndian::read_u32(&mft_record0[attr_offset..attr_offset + 4]);
        if attr_type == 0xFFFFFFFF || attr_type == 0 { break; }

        let attr_len = LittleEndian::read_u32(&mft_record0[attr_offset + 4..attr_offset + 8]) as usize;
        if attr_len == 0 || attr_offset.checked_add(attr_len).unwrap_or(usize::MAX) > used_end {
            fatal("Выход размера атрибута за границы используемой части записи.");
        }
        
        let attr_end = attr_offset + attr_len;
        let non_resident = mft_record0[attr_offset + 8] != 0;
        let main_name_len = mft_record0[attr_offset + 9]; 

        if attr_type == 0x20 { 
            if !non_resident {
                let value_len = LittleEndian::read_u32(&mft_record0[attr_offset + 16..attr_offset + 20]) as usize;
                let value_off = LittleEndian::read_u16(&mft_record0[attr_offset + 20..attr_offset + 22]) as usize;
                
                let list_start = attr_offset.checked_add(value_off).unwrap_or(usize::MAX);
                let list_end = list_start.checked_add(value_len).unwrap_or(usize::MAX);
                
                if list_start < attr_offset || list_end > attr_end {
                    fatal("$ATTRIBUTE_LIST выходит за границы атрибута.");
                }
                
                let mut curr = list_start;
                while curr + 26 <= list_end {
                    let entry_type = LittleEndian::read_u32(&mft_record0[curr..curr + 4]);
                    if entry_type == 0 { break; }
                    let entry_len = LittleEndian::read_u16(&mft_record0[curr + 4..curr + 6]) as usize;
                    if entry_len < 26 || curr.checked_add(entry_len).unwrap_or(usize::MAX) > list_end { break; }
                    
                    let name_len = mft_record0[curr + 6] as usize; 
                    let name_off = mft_record0[curr + 7] as usize; 
                    
                    if name_off.checked_add(name_len * 2).unwrap_or(usize::MAX) > entry_len {
                        fatal("Длина имени UTF-16 в $ATTRIBUTE_LIST выходит за пределы записи.");
                    }
                    
                    if entry_type == 0x80 && name_len == 0 {
                        let start_vcn = LittleEndian::read_u64(&mft_record0[curr + 8..curr + 16]);
                        let base_ref = LittleEndian::read_u64(&mft_record0[curr + 16..curr + 24]);
                        let entry = base_ref & 0xFFFFFFFFFFFF;
                        let seq = (base_ref >> 48) as u16;
                        if entry != 0 {
                            attr_list_entries.push(ExtentTarget { start_vcn, entry, seq });
                        }
                    }
                    curr += entry_len;
                }
            } else {
                let al_svcn = LittleEndian::read_u64(&mft_record0[attr_offset + 0x10..attr_offset + 0x18]);
                let dr_off = LittleEndian::read_u16(&mft_record0[attr_offset + 0x20..attr_offset + 0x22]) as usize;
                let actual_size = LittleEndian::read_u64(&mft_record0[attr_offset + 0x30..attr_offset + 0x38]) as usize;

                if dr_off < 0x40 || attr_offset.checked_add(dr_off).unwrap_or(usize::MAX) >= attr_end {
                    fatal("Некорректное смещение Data Runs (dr_off) в non-resident $ATTRIBUTE_LIST.");
                }

                let al_runs = match parse_data_runs(&mft_record0, attr_offset + dr_off, attr_end, al_svcn) {
                    Ok(runs) => runs,
                    Err(e) => fatal(&format!("Ошибка runlist в non-resident $ATTRIBUTE_LIST: {}", e)),
                };

                let mut covered_clusters: u64 = 0;
                for r in &al_runs {
                    covered_clusters = covered_clusters.checked_add(r.length)
                        .unwrap_or_else(|| fatal("Переполнение при подсчете al_runs"));
                }
                let covered_bytes = covered_clusters.checked_mul(bytes_per_cluster)
                    .unwrap_or_else(|| fatal("Переполнение covered_bytes"));
                if covered_bytes < actual_size as u64 {
                    fatal("Runlist non-resident $ATTRIBUTE_LIST короче actual_size");
                }

                if actual_size == 0 || actual_size > 1024 * 1024 {
                    fatal(&format!("Недопустимый размер non-resident $ATTRIBUTE_LIST: {} байт", actual_size));
                }

                let al_logical_offset = al_svcn.checked_mul(bytes_per_cluster).unwrap_or_else(|| fatal("Переполнение смещения al_svcn"));
                let mut attr_list_buf = vec![0u8; actual_size];
                
                if let Err(e) = read_logical_mft(&mut vol, &al_runs, bytes_per_cluster, partition_offset, al_logical_offset, &mut attr_list_buf) {
                    fatal(&format!("Ошибка чтения non-resident $ATTRIBUTE_LIST: {}", e));
                }

                let mut curr = 0;
                while curr + 26 <= actual_size {
                    let entry_type = LittleEndian::read_u32(&attr_list_buf[curr..curr + 4]);
                    if entry_type == 0 { break; }
                    let entry_len = LittleEndian::read_u16(&attr_list_buf[curr + 4..curr + 6]) as usize;
                    if entry_len < 26 || curr.checked_add(entry_len).unwrap_or(usize::MAX) > actual_size { break; }

                    let name_len = attr_list_buf[curr + 6] as usize;
                    let name_off = attr_list_buf[curr + 7] as usize;

                    if name_off.checked_add(name_len * 2).unwrap_or(usize::MAX) > entry_len {
                        fatal("Длина имени UTF-16 в non-resident $ATTRIBUTE_LIST выходит за пределы записи.");
                    }

                    if entry_type == 0x80 && name_len == 0 {
                        let start_vcn = LittleEndian::read_u64(&attr_list_buf[curr + 8..curr + 16]);
                        let base_ref = LittleEndian::read_u64(&attr_list_buf[curr + 16..curr + 24]);
                        let entry = base_ref & 0xFFFFFFFFFFFF;
                        let seq = (base_ref >> 48) as u16;
                        if entry != 0 {
                            attr_list_entries.push(ExtentTarget { start_vcn, entry, seq });
                        }
                    }
                    curr += entry_len;
                }
            }
        } else if attr_type == 0x80 && main_name_len == 0 { 
            if non_resident {
                let start_vcn = LittleEndian::read_u64(&mft_record0[attr_offset + 16..attr_offset + 24]);
                let dr_off = LittleEndian::read_u16(&mft_record0[attr_offset + 32..attr_offset + 34]) as usize;
                
                if attr_offset + 0x30 <= attr_end {
                    expected_allocated_size = LittleEndian::read_u64(&mft_record0[attr_offset + 0x28..attr_offset + 0x30]);
                }
                
                if dr_off < 0x40 || attr_offset.checked_add(dr_off).unwrap_or(usize::MAX) >= attr_end {
                    fatal("Некорректное смещение Data Runs (dr_off).");
                }
                
                match parse_data_runs(&mft_record0, attr_offset + dr_off, attr_end, start_vcn) {
                    Ok(runs) => base_runs.extend(runs),
                    Err(e) => fatal(&format!("Ошибка runlist в Record 0: {}", e)),
                }
            }
        }
        attr_offset = attr_end;
    }

    if base_runs.is_empty() {
        fatal("Базовые Data Runs для $MFT не найдены.");
    }

    let mut all_runs = base_runs.clone();

    // Сбор экстентов
    for target in attr_list_entries {
        let record_byte_offset = target.entry.checked_mul(record_size as u64)
            .unwrap_or_else(|| fatal("Переполнение при вычислении логического смещения экстента"));
            
        let mut ext_record = vec![0u8; record_size];
        
        if let Err(e) = read_logical_mft(&mut vol, &base_runs, bytes_per_cluster, partition_offset, record_byte_offset, &mut ext_record) {
            fatal(&format!("Ошибка чтения ext_record ({}): {}", target.entry, e));
        }
        
        let eh = match MftRecordHeader::parse(&ext_record) {
            Some(h) => h,
            None => fatal(&format!("ext_record поврежден ({})", target.entry)),
        };
        
        if let Err(e) = validate_record_boundaries(&eh, record_size, false) {
            fatal(&format!("ext_record ({}) отбракован: {}", target.entry, e));
        }

        if eh.sequence_number != target.seq {
            fatal(&format!("Sequence mismatch в ext_record {}. Ожидался {}, найден {}.", target.entry, target.seq, eh.sequence_number));
        }
        
        if apply_fixups(&mut ext_record, &eh, boot.bytes_per_sector) == FixupResult::Failed {
            fatal(&format!("Ошибка fixups в ext_record ({})", target.entry));
        }
        
        let mut e_off = eh.first_attribute_offset as usize;
        let e_used = eh.real_size as usize;
        let mut e_prev = 0;
        
        while e_off + 8 <= e_used {
            if e_off <= e_prev && e_prev != 0 { break; }
            e_prev = e_off;

            let e_type = LittleEndian::read_u32(&ext_record[e_off..e_off + 4]);
            if e_type == 0xFFFFFFFF || e_type == 0 { break; }
            let e_len = LittleEndian::read_u32(&ext_record[e_off + 4..e_off + 8]) as usize;
            if e_len == 0 || e_off.checked_add(e_len).unwrap_or(usize::MAX) > e_used { break; }
            
            let e_attr_end = e_off + e_len;
            let non_resident = ext_record[e_off + 8] != 0;
            let e_name_len = ext_record[e_off + 9];

            if e_type == 0x80 && non_resident && e_name_len == 0 {
                let svcn = LittleEndian::read_u64(&ext_record[e_off + 16..e_off + 24]);
                if svcn == target.start_vcn {
                    let dr_off = LittleEndian::read_u16(&ext_record[e_off + 32..e_off + 34]) as usize;
                    if dr_off < 0x40 || e_off.checked_add(dr_off).unwrap_or(usize::MAX) >= e_attr_end {
                        fatal(&format!("Некорректное смещение Data Runs (dr_off) в экстенте {}.", target.entry));
                    }
                    
                    match parse_data_runs(&ext_record, e_off + dr_off, e_attr_end, target.start_vcn) {
                        Ok(runs) => all_runs.extend(runs),
                        Err(e) => fatal(&format!("Ошибка runlist в ext_record ({}): {}", target.entry, e)),
                    }
                }
            }
            e_off += e_len;
        }
    }

    all_runs.sort_by_key(|r| r.vcn_start);

    if all_runs.is_empty() { fatal("Итоговый Runlist пуст."); }
    if all_runs[0].vcn_start != 0 { fatal(&format!("Дыра в VCN с самого начала. Ожидался 0, найден {}.", all_runs[0].vcn_start)); }

    let mut expected_vcn = 0;
    for run in &all_runs {
        if run.vcn_start > expected_vcn { fatal(&format!("Дыра в VCN. Ожидался {}, найден {}.", expected_vcn, run.vcn_start)); } 
        else if run.vcn_start < expected_vcn { fatal(&format!("Перекрытие VCN. Ожидался {}, найден {}.", expected_vcn, run.vcn_start)); }
        expected_vcn = expected_vcn.checked_add(run.length).unwrap_or_else(|| fatal("Переполнение суммы VCN."));
    }
    
    let expected_total_bytes = expected_vcn.checked_mul(bytes_per_cluster).unwrap_or_else(|| fatal("Переполнение при вычислении итогового размера MFT."));

    if expected_allocated_size > 0 && expected_total_bytes < expected_allocated_size {
        fatal(&format!("Собранный по кластерам размер MFT ({} байт) меньше заявленного Allocated Size ({} байт). Runlist поврежден.", expected_total_bytes, expected_allocated_size));
    }

    let mut extracted_bytes: u64 = 0;
    println!("[*] Извлечение: Строгий режим, размер {} байт", expected_total_bytes);
    let mut out_file = match File::create(out) {
        Ok(f) => f,
        Err(e) => fatal(&format!("Не удалось создать {}: {}", out, e)),
    };

    for run in all_runs {
        let bytes_to_read = run.length.checked_mul(bytes_per_cluster).unwrap_or_else(|| fatal("Переполнение bytes_to_read."));

        if run.is_sparse {
            let chunk = vec![0u8; 1024 * 1024];
            let mut remaining = bytes_to_read;
            while remaining > 0 {
                let to_write = std::cmp::min(remaining, chunk.len() as u64) as usize;
                out_file.write_all(&chunk[..to_write]).unwrap_or_else(|e| fatal(&format!("Ошибка записи разреженных нулей: {}", e)));
                remaining -= to_write as u64;
                extracted_bytes += to_write as u64;
            }
            continue;
        }

        let physical_offset = partition_offset.checked_add(run.lcn.checked_mul(bytes_per_cluster).unwrap_or_else(|| fatal("Переполнение lcn * bpc"))).unwrap_or_else(|| fatal("Переполнение partition_offset + LCN offset"));
        vol.seek(SeekFrom::Start(physical_offset)).unwrap_or_else(|e| fatal(&format!("Ошибка seek на физический offset {}: {}", physical_offset, e)));

        let mut chunk = vec![0u8; 1024 * 1024];
        let mut remaining = bytes_to_read;
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, chunk.len() as u64) as usize;
            let buffer_slice = &mut chunk[..to_read];
            
            vol.read_exact(buffer_slice).unwrap_or_else(|e| fatal(&format!("Недочитка байтов с диска. Осталось прочитать: {}. Ошибка: {}", remaining, e)));
            out_file.write_all(buffer_slice).unwrap_or_else(|e| fatal(&format!("Ошибка записи в файл дампа: {}", e)));
            
            remaining -= to_read as u64;
            extracted_bytes += to_read as u64;
        }
    }

    if extracted_bytes != expected_total_bytes { fatal(&format!("Извлечено {} байт, ожидалось {}.", extracted_bytes, expected_total_bytes)); }

    println!("[+] Успешно извлечено: {} МБ.", extracted_bytes / 1024 / 1024);

    let meta = MftMeta {
        bytes_per_sector: boot.bytes_per_sector, sectors_per_cluster: boot.sectors_per_cluster,
        bytes_per_cluster, mft_lcn: boot.mft_lcn, mft_mirror_lcn: boot.mft_mirror_lcn,
        clusters_per_index_buffer: boot.clusters_per_index_buffer, mft_record_size: record_size as u32,
        volume_serial_number: boot.volume_serial_number, source: volume_path,
    };

    if let Ok(mut f) = File::create(format!("{}.meta.json", out)) {
        let _ = serde_json::to_writer_pretty(&mut f, &meta);
        let _ = f.write_all(b"\n");
    }
}
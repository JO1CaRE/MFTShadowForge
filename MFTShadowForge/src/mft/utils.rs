use chrono::{DateTime, TimeZone, Utc};

/// Конвертирует Windows FILETIME (100-нс интервалы с 1601-01-01) в DateTime<Utc>
pub fn filetime_to_datetime(filetime: u64) -> DateTime<Utc> {
    // 116444736000000000 = количество 100-нс интервалов между 1601-01-01 и 1970-01-01 (Unix Epoch)
    let unix_time_100ns = filetime.saturating_sub(116_444_736_000_000_000);
    let seconds = (unix_time_100ns / 10_000_000) as i64;
    let nanoseconds = ((unix_time_100ns % 10_000_000) * 100) as u32;
    
    // Используем .single(), чтобы получить Option из LocalResult
    Utc.timestamp_opt(seconds, nanoseconds)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap())
}
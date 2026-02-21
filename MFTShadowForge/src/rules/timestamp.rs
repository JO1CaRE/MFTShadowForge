use chrono::{DateTime, Utc, Timelike};

pub struct TimestampData {
    pub si_c: DateTime<Utc>,
    pub si_m: DateTime<Utc>,
    pub si_e: DateTime<Utc>, // Record Change (MFT Modified)
    pub si_a: DateTime<Utc>,
    pub fn_c: DateTime<Utc>,
    pub fn_m: DateTime<Utc>,
    pub fn_e: DateTime<Utc>,
    pub fn_a: DateTime<Utc>,
}

impl TimestampData {
    /// Rule 2: Нулевые доли секунды в SI и их отсутствие в FN
    pub fn has_usec_zeros(&self) -> bool {
        let si_zeros = [self.si_c, self.si_m, self.si_e, self.si_a]
            .iter()
            .filter(|t| t.nanosecond() == 0)
            .count();
            
        let fn_zeros = [self.fn_c, self.fn_m, self.fn_e, self.fn_a]
            .iter()
            .filter(|t| t.nanosecond() == 0)
            .count();
            
        si_zeros >= 3 && fn_zeros <= 1
    }

    /// Эвристика: Файл был скопирован (Created > Modified)
    pub fn is_copied(&self) -> bool {
        self.si_c > self.si_m
    }

    /// Rule 1: SI раньше FN (классический timestamp mismatch)
    pub fn is_timestomped(&self) -> bool {
        // Порог T1 = 1 секунда (1000 миллисекунд), чтобы исключить микро-погрешности ОС
        let t1_ms = 100000;
        
        (self.fn_c.timestamp_millis() - self.si_c.timestamp_millis() > t1_ms) ||
        (self.fn_m.timestamp_millis() - self.si_m.timestamp_millis() > t1_ms) ||
        (self.fn_e.timestamp_millis() - self.si_e.timestamp_millis() > t1_ms) ||
        (self.fn_a.timestamp_millis() - self.si_a.timestamp_millis() > t1_ms)
    }

    /// Rule 3: Время “раньше создания тома”
    pub fn is_before_volume_birth(&self, volume_birth: Option<DateTime<Utc>>) -> bool {
        if let Some(vb) = volume_birth {
            // Если SI Creation раньше создания тома (с допуском 1 сек на округление)
            self.si_c.timestamp_millis() < vb.timestamp_millis() - 1000
        } else {
            false
        }
    }
}
use serde::Serialize;
use std::io::{self, Write};

/// Потоковая запись в формате JSONL (JSON Lines).
/// - Одна запись - один JSON-объект
/// - Каждый объект заканчивается '\n'
/// - Нет массива, запятых и закрывающих скобок
pub struct JsonlWriter<W: Write> {
    inner: W,
}

impl<W: Write> JsonlWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    pub fn write<T: Serialize>(&mut self, value: &T) -> io::Result<()> {
        serde_json::to_writer(&mut self.inner, value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.inner.write_all(b"\n")?;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
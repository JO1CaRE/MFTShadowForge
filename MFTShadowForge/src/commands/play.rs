use std::path::{Path, PathBuf};

use super::extract;
use super::parse;

pub fn run(image: &str, out_dir: &str, data_flag: bool) {
    println!("[*] Запуск полного пайплайна (Play)");

    if !Path::new(out_dir).exists() {
        std::fs::create_dir_all(out_dir).unwrap();
    }

    let out_dir = PathBuf::from(out_dir);
    let mft_path = out_dir.join("MFT");
    let jsonl_path = out_dir.join("REPORT");

    extract::run(image, mft_path.to_string_lossy().as_ref());

    parse::run(
        mft_path.to_string_lossy().as_ref(),
        jsonl_path.to_string_lossy().as_ref(),
        data_flag,
    );

    println!(
        "\n[+] Пайплайн успешно завершен! Результаты в папке: {}",
        out_dir.display()
    );
}
use clap::{Parser, Subcommand};

const ASCII_LOGO: &str = r#"
                                ___  _________ _____ _____ _               _              ______                   
                                |  \/  ||  ___|_   _/  ___| |             | |             |  ___|                  
                                | .  . || |_    | | \ `--.| |__   __ _  __| | _____      _| |_ ___  _ __ __ _  ___ 
                                | |\/| ||  _|   | |  `--. \ '_ \ / _` |/ _` |/ _ \ \ /\ / /  _/ _ \| '__/ _` |/ _ \
                                | |  | || |     | | /\__/ / | | | (_| | (_| | (_) \ V  V /| || (_) | | | (_| |  __/
                                \_|  |_/\_|     \_/ \____/|_| |_|\__,_|\__,_|\___/ \_/\_/ \_| \___/|_|  \__, |\___|
                                                                                                        __/ |     
                                                                                                        |___/      
"#;

const EXAMPLES: &str = r#"
ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ:

  1. ИЗВЛЕЧЕНИЕ (Extract)
     Извлечь сырой MFT с работающего диска C: в файл mft.raw:
     MFTShadowForge.exe extract --image C: --out C:\MftDump\mft.raw
     
     Или коротко:
     MFTShadowForge.exe extract -i C: -o C:\MftDump\mft.raw

  2. АНАЛИЗ (Parse)
     Распарсить дамп MFT в формат JSONL с извлечением бинарных данных ($DATA):
     MFTShadowForge.exe parse --path C:\MftDump\mft.raw --out-json C:\MftDump\report.jsonl --data
     
     Или коротко:
     MFTShadowForge.exe parse -p mft.raw -j report.jsonl -d

  3. ПОЛНЫЙ ЦИКЛ (Play)
     Автоматически извлечь MFT с диска C: и сразу запустить анализ в указанную папку:
     MFTShadowForge.exe play --image C: --out C:\MftDump --data
     
     Или коротко:
     MFTShadowForge.exe play -i C: -o C:\MftDump -d
"#;

#[derive(Parser, Debug)]
#[command(name = "MFTShadowForge")]
#[command(version = "1.0")]
#[command(before_help = ASCII_LOGO)] // Вставляем логотип НАД меню
#[command(about = "DFIR tool for NTFS MFT parsing and analysis")]
#[command(after_help = EXAMPLES)]    // Вставляем примеры ПОД меню
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Извлекает MFT в raw-формат из образа диска
    Extract {
        /// Образ диска (E01/raw) или условный C:\
        #[arg(short, long)]
        image: String,
        /// Путь к raw MFT
        #[arg(short, long)]
        out: String,
    },
    /// Конвертирует raw MFT в JSONL (JSON Lines) с анализом и правилами
    Parse {
        /// Путь к raw MFT
        #[arg(short, long)]
        path: String,
        /// Путь к итоговому JSONL (1 строка - 1 объект)
        #[arg(short = 'j', long)]
        out_json: String,
        /// Включать ли содержимое $DATA для резидентных файлов
        #[arg(short, long)]
        data: bool,
    },
    /// Полный пайплайн (extract + parse)
    Play {
        /// Образ диска (E01/raw) или условный C:\
        #[arg(short, long)]
        image: String,
        /// Папка для raw MFT и JSONL
        #[arg(short, long)]
        out: String,
        /// Включать ли содержимое $DATA для резидентных файлов
        #[arg(short, long)]
        data: bool,
    },
}
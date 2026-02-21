use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub struct PathBuilder {
    // entry_num -> (parent_entry_num, parent_sequence_number, self_sequence_number, name)
    entries: HashMap<u64, (u64, u16, u16, String)>,
}

impl PathBuilder {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    pub fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
    }

    pub fn add_entry(&mut self, entry_num: u64, self_seq: u16, parent_num: u64, parent_seq: u16, name: String) {
        self.entries.insert(entry_num, (parent_num, parent_seq, self_seq, name));
    }

    pub fn get_full_path(&self, entry_num: u64, expected_seq: u16) -> String {
        let mut path_parts = Vec::new();
        let mut current_entry = entry_num;
        let mut current_expected_seq = expected_seq;
        let mut visited = HashSet::new();

        while let Some(&(parent_num, parent_seq, self_seq, ref name)) = self.entries.get(&current_entry) {
            if !visited.insert(current_entry) {
                path_parts.push(String::from("<CORRUPTED_LOOP>"));
                break;
            }

            // ИЗМЕНЕНИЕ 2.2: Проверка Sequence Number (защита от Orphan путей для удаленных файлов)
            if current_expected_seq != 0 && self_seq != current_expected_seq {
                path_parts.push(String::from("<ORPHAN_OR_REALLOCATED>"));
                break;
            }

            if name != "." {
                path_parts.push(name.clone());
            }

            if current_entry == 5 || parent_num == current_entry {
                break;
            }

            current_entry = parent_num;
            current_expected_seq = parent_seq;
        }

        path_parts.reverse();
        if path_parts.is_empty() {
            String::from("\\")
        } else {
            format!("\\{}", path_parts.join("\\"))
        }
    }

    pub fn get_parent_path(&self, parent_num: u64, parent_seq: u16) -> String {
        let mut parent = self.get_full_path(parent_num, parent_seq);
        if parent.is_empty() {
            parent = String::from("\\");
        }
        parent
    }
}
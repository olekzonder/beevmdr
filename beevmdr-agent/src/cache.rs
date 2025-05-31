// src/hash_table.rs

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{self, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct Key {
    pub filename: String,
}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.filename.hash(state);
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.filename == other.filename
    }
}

impl Eq for Key {}

#[derive(Clone, Debug)]
pub struct Value {
    pub sha256: String,
    pub version: String,
    pub checked: bool,
}

pub type SharedTable = Arc<Mutex<HashMap<Key, Value>>>;
pub fn new_shared_table() -> SharedTable {
    Arc::new(Mutex::new(HashMap::new()))
}

pub fn lookup_or_insert<P: AsRef<Path>>(table: &SharedTable, filename: P) -> Option<Value> {
    let key = Key {
        filename: filename.as_ref().to_string_lossy().into_owned(),
    };

    let mut table = table.lock().unwrap();

    if let Some(value) = table.get(&key).cloned() {
        return Some(value);
    }

    match compute_file_metadata(filename) {
        Ok(value) => {
            table.insert(key, value.clone());
            Some(value)
        }
        Err(_e) => None,
    }
}

pub fn compute_sha256<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;

    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

pub fn compute_file_metadata<P: AsRef<Path>>(path: P) -> io::Result<Value> {
    let sha256 = compute_sha256(&path)?;
    Ok(Value {
        sha256: sha256,
        version: "unknown".to_string(),
        checked: false,
    })
}

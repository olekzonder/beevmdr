use reqwest::blocking::Client;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;

pub struct BazaarHashDB {
    hashes: HashSet<String>,
}

impl BazaarHashDB {
    pub fn load(file_path: &str) -> io::Result<Self> {
        let path = Path::new(file_path);

        if !path.exists() {
            println!("{} not found. Downloading...", file_path);
            Self::download_file(file_path)?;
        }

        let hashes = Self::parse_file(file_path)?;

        Ok(BazaarHashDB { hashes })
    }

    fn download_file(file_path: &str) -> io::Result<()> {
        let url = "https://bazaar.abuse.ch/export/txt/sha256/recent/";

        let client = Client::new();
        let response = client.get(url).send().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to download file: {}", e),
            )
        })?;

        let content = response.text().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to read response text: {}", e),
            )
        })?;

        fs::write(file_path, content)?;
        println!("Downloaded bazaar.txt to {}", file_path);
        Ok(())
    }

    fn parse_file(file_path: &str) -> io::Result<HashSet<String>> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        let mut hashes = HashSet::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();

            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }

            if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                hashes.insert(trimmed.to_string());
            } else {
                eprintln!("Invalid SHA256 line: {}", trimmed);
            }
        }

        Ok(hashes)
    }

    pub fn contains_hash(&self, hash: &str) -> bool {
        self.hashes.contains(hash)
    }
}

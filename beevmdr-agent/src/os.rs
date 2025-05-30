use std::collections::HashMap;
use std::fs;
use std::io;
use std::process::Command;
use std::sync::{Arc, Mutex};

pub type SharedOS = Arc<Mutex<OS>>;
pub fn new_shared_os() -> SharedOS {
    Arc::new(Mutex::new(OS::new()))
}

trait OSImpl {
    fn get_package_version(&self, filename: &str) -> Result<String, String>;
}

pub(crate) struct OS {
    impl_: Box<dyn OSImpl>,
}

fn get_os_info() -> HashMap<String, String> {
    let content = fs::read_to_string("/etc/os-release")
        .or_else(|_| fs::read_to_string("/usr/lib/os-release"))
        .expect("Unable to open os-release");
    let mut map = HashMap::new();

    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim_matches(|c| c == '"' || c == '\'');
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

impl OS {
    pub fn new() -> Self {
        let os_info = get_os_info();
        let os_id = os_info.get("ID").map(|s| s.to_lowercase());

        let impl_: Box<dyn OSImpl> = match os_id.as_deref() {
            Some("debian") | Some("ubuntu") | Some("astra linux") => Box::new(DebianOS),
            _ => Box::new(NotImplementedOS),
        };

        Self { impl_ }
    }

    pub fn check_package_version(&self, package_name: &str) -> Result<String, String> {
        self.impl_.get_package_version(package_name)
    }
}

struct NotImplementedOS;
impl OSImpl for NotImplementedOS {
    fn get_package_version(&self, _package_name: &str) -> Result<String, String> {
        Err("Unknown OS".to_string())
    }
}

struct DebianOS;
impl OSImpl for DebianOS {
    fn get_package_version(&self, package_name: &str) -> Result<String, String> {
        // Проверяем, принадлежит ли файл пакету
        let dpkg_output = Command::new("dpkg")
            .arg("-S")
            .arg(package_name)
            .output()
            .map_err(|e| e.to_string())?;

        if !dpkg_output.status.success() {
            return Err(
                "Файл не принадлежит ни одному пакету или произошла ошибка dpkg".to_string(),
            );
        }

        let output_str = String::from_utf8_lossy(&dpkg_output.stdout);
        let package_info = output_str
            .split(':')
            .next()
            .ok_or("Неожиданный формат вывода dpkg")?;

        // Получаем информацию о пакете
        let version_output = Command::new("dpkg")
            .arg("-s")
            .arg(package_info)
            .output()
            .map_err(|e| e.to_string())?;

        if !version_output.status.success() {
            return Err("Не удалось получить информацию о пакете".to_string());
        }

        let version_str = String::from_utf8_lossy(&version_output.stdout);
        for line in version_str.lines() {
            if line.starts_with("Version:") {
                let version = line
                    .split(':')
                    .nth(1)
                    .map(str::trim)
                    .unwrap_or("неизвестно");

                return Ok(format!("{}: {}", package_info, version));
            }
        }

        Err("Информация о версии отсутствует в данных пакета".to_string())
    }
}

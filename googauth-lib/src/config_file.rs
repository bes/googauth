use dirs::home_dir;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::{create_dir_all, set_permissions, File, Permissions};
use std::io::{BufReader, BufWriter};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use crate::errors::LibError;

/// A configuration file that saves the information necessary
/// to fetch tokens and to be able to refresh said tokens when
/// needed.
#[derive(Serialize, Deserialize)]
pub struct ConfigFile {
    pub version: u32,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub redirect_url: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<Token>,
    pub access_token: Option<Token>,
}

impl ConfigFile {
    pub fn new(
        name: &str,
        client_id: &str,
        client_secret: &str,
        scopes: &[String],
        redirect_url: &str,
    ) -> ConfigFile {
        ConfigFile {
            version: 1,
            name: name.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            redirect_url: redirect_url.to_string(),
            refresh_token: None,
            id_token: None,
            access_token: None,
        }
    }
}

pub struct ConfigBasePath {
    path: PathBuf,
}

impl ConfigBasePath {
    pub fn default() -> Result<ConfigBasePath, LibError> {
        let mut config_dir = match home_dir() {
            None => {
                return Err(LibError::HomeDirectoryNotFound);
            }
            Some(dir) => dir,
        };
        config_dir.push(".googauth");
        Ok(ConfigBasePath { path: config_dir } )
    }

    pub fn from(path: PathBuf) -> ConfigBasePath {
        ConfigBasePath { path }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Token {
    pub secret: String,
    pub exp: u64,
}

impl Token {
    pub fn new(secret: String, exp: u64) -> Token {
        Token { secret, exp }
    }
}

impl ConfigFile {
    pub fn config_file(name: &str, config_base_path: &ConfigBasePath) -> Result<PathBuf, LibError> {
        let mut config_dir = config_base_path.path.clone();
        config_dir.push(name);
        Ok(config_dir)
    }

    pub fn list_configs(config_base_path: &ConfigBasePath) -> Result<Vec<ConfigFile>, LibError> {
        let config_dir = config_base_path.path.clone();

        if config_dir.is_dir() {
            let mut result = Vec::new();
            let dirs = fs::read_dir(config_dir)?;
            for entry in dirs {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let file_name = path.file_name().ok_or(LibError::FilenameError)?.to_str().ok_or(LibError::FilenameError)?;
                    if let Ok(config_file) = ConfigFile::read_config(file_name, config_base_path) {
                        result.push(config_file);
                    }
                }
            }
            return Ok(result);
        }
        Err(LibError::ConfigsDirectoryNotADirectory(config_dir))
    }

    pub fn read_config(name: &str, config_base_path: &ConfigBasePath) -> Result<ConfigFile, LibError> {
        let config_dir = ConfigFile::config_file(name, config_base_path)?;

        let config_file = File::open(config_dir.as_path())?;
        let config_file_reader = BufReader::new(config_file);
        let config = serde_json::from_reader(config_file_reader)?;
        Ok(config)
    }

    pub fn save_config(&self, config_base_path: &ConfigBasePath) -> Result<(), LibError> {
        let mut config_dir = config_base_path.path.clone();

        create_dir_all(config_dir.as_path())?;
        if cfg!(unix) {
            set_permissions(config_dir.as_path(), Permissions::from_mode(0o700))?
        }

        config_dir.push(self.name.to_string());

        let config_file = File::create(config_dir.as_path())?;

        if cfg!(unix) {
            set_permissions(config_dir.as_path(), Permissions::from_mode(0o600))?;
        }

        let config_file_writer = BufWriter::new(config_file);

        serde_json::to_writer(config_file_writer, self)?;

        Ok(())
    }
}

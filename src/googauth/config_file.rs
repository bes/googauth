use dirs::home_dir;
use serde::{Deserialize, Serialize};
use simple_error::SimpleError;
use std::fs::{create_dir_all, set_permissions, File, Permissions};
use std::io::{BufReader, BufWriter};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

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
        scopes: &Vec<String>,
        redirect_url: &str,
    ) -> ConfigFile {
        ConfigFile {
            version: 1,
            name: name.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            scopes: scopes.into_iter().map(|s| s.to_string()).collect(),
            redirect_url: redirect_url.to_string(),
            refresh_token: None,
            id_token: None,
            access_token: None,
        }
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
    pub fn googauth_dir() -> Option<PathBuf> {
        let mut config_dir = match home_dir() {
            None => {
                return None;
            }
            Some(dir) => dir,
        };
        config_dir.push(".googauth");
        Some(config_dir)
    }

    pub fn googauth_file(name: &str) -> Option<PathBuf> {
        let mut config_dir = ConfigFile::googauth_dir()?;
        config_dir.push(name);
        Some(config_dir)
    }

    pub fn read_config(name: &str) -> Option<ConfigFile> {
        let config_dir = ConfigFile::googauth_file(name)?;

        let config_file = match File::open(config_dir.as_path()) {
            Ok(f) => f,
            Err(_) => {
                return None;
            }
        };
        let config_file_reader = BufReader::new(config_file);
        match serde_json::from_reader(config_file_reader) {
            Ok(s) => Some(s),
            Err(_) => {
                return None;
            }
        }
    }

    pub fn save_config(&self) -> Result<(), SimpleError> {
        let mut config_dir =
            require_with!(ConfigFile::googauth_dir(), "Could not get home directory");

        match create_dir_all(config_dir.as_path()) {
            Ok(_) => {
                if cfg!(unix) {
                    match set_permissions(config_dir.as_path(), Permissions::from_mode(0o700)) {
                        Ok(()) => (),
                        Err(e) => {
                            return Err(SimpleError::from(e));
                        }
                    }
                } else {
                    ()
                }
            }
            Err(e) => {
                return Err(SimpleError::from(e));
            }
        };

        config_dir.push(self.name.to_string());

        let config_file = match File::create(config_dir.as_path()) {
            Ok(f) => f,
            Err(e) => {
                return Err(SimpleError::from(e));
            }
        };

        if cfg!(unix) {
            match set_permissions(config_dir.as_path(), Permissions::from_mode(0o600)) {
                Ok(()) => (),
                Err(e) => {
                    return Err(SimpleError::from(e));
                }
            }
        }

        let config_file_writer = BufWriter::new(config_file);

        match serde_json::to_writer(config_file_writer, self) {
            Ok(_) => (),
            Err(e) => {
                return Err(SimpleError::from(e));
            }
        }

        return Ok(());
    }
}

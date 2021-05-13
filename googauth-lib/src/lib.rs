use std::time::{SystemTime, UNIX_EPOCH};

pub use config_file::*;
pub use login_flow::google_login;
pub use refresh_flow::refresh_google_login;

pub use crate::errors::LibError;

mod config_file;
mod errors;
mod login_flow;
mod refresh_flow;

/// Given a config name, that has been previously saved by [config_file::ConfigFile],
/// fetch the access token, potentially refreshing it if needed.
pub fn get_access_token_from_config(
    config_name: &str,
    config_base_path: &ConfigBasePath,
) -> Result<Token, LibError> {
    let mut config = ConfigFile::read_config(config_name, config_base_path)?;

    check_token(config.access_token.clone(), &mut config, config_base_path)?;

    match &config.access_token {
        Some(access_token) => Ok(access_token.clone()),
        None => Err(LibError::CouldNotReadConfigCorrupt(config.name)),
    }
}

/// Given an optional [config_file::Token] and a [config_file::ConfigFile],
/// check if it's valid and potentially refresh it if it is not.
pub fn check_token(
    token: Option<Token>,
    config: &mut ConfigFile,
    config_base_path: &ConfigBasePath,
) -> Result<(), LibError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token_expiration = match token {
        Some(token) => token.exp,
        None => 0,
    };

    if token_expiration < now {
        refresh_google_login(config, config_base_path)?;
    }

    Ok(())
}

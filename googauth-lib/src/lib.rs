pub use crate::errors::LibError;
pub use config_file::*;
pub use login_flow::google_login;
pub use openidconnect::{AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse, http};
pub use refresh_flow::refresh_google_login;
use std::time::{SystemTime, UNIX_EPOCH};

mod config_file;
mod errors;
mod login_flow;
mod refresh_flow;

/// Given a config name, that has been previously saved by [config_file::ConfigFile],
/// fetch the access token, potentially refreshing it if needed.
///
/// See [refresh_google_login] for the requirements on `http_client`.
pub async fn get_access_token_from_config<C: for<'c> AsyncHttpClient<'c>>(
    config_name: &str,
    config_base_path: &ConfigBasePath,
    http_client: &C,
) -> Result<Token, LibError> {
    let mut config = ConfigFile::read_config(config_name, config_base_path)?;

    check_token(
        config.access_token.clone(),
        &mut config,
        config_base_path,
        http_client,
    )
    .await?;

    match &config.access_token {
        Some(access_token) => Ok(access_token.clone()),
        None => Err(LibError::CouldNotReadConfigCorrupt(config.name)),
    }
}

/// Given an optional [config_file::Token] and a [config_file::ConfigFile],
/// check if it's valid and potentially refresh it if it is not.
///
/// See [refresh_google_login] for the requirements on `http_client`.
pub async fn check_token<C: for<'c> AsyncHttpClient<'c>>(
    token: Option<Token>,
    config: &mut ConfigFile,
    config_base_path: &ConfigBasePath,
    http_client: &C,
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
        refresh_google_login(config, config_base_path, http_client).await?;
    }

    Ok(())
}

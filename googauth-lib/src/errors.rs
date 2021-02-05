use thiserror::Error;
use std::path::PathBuf;

#[derive(Error, Debug)]
pub enum LibError {
    #[error("No such configuration: {0}")]
    NoSuchConfiguration(String),
    #[error("Can not find home directory")]
    HomeDirectoryNotFound,
    #[error("Configs directory {0} is not a directory")]
    ConfigsDirectoryNotADirectory(PathBuf),
    #[error("Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Filename error")]
    FilenameError,
    #[error("JSON error {0:?}")]
    JsonError(#[from] serde_json::Error),
    #[error("URL parse error {0:?}")]
    UrlError(#[from] url::ParseError),
    #[error("The state sent to the server, and the state received from the server do not match - this may be a sign of a CSRF attack")]
    TokenCsrfError,
    #[error("No ID token present")]
    NoIdToken,
    #[error("No refresh token present")]
    NoRefreshToken,
    #[error("Could not refresh token")]
    CouldNotRefreshToken,
    #[error("Could not read claims")]
    CouldNotReadClaims,
    #[error("There were no scopes in the response")]
    NoScopes,
    #[error("Could not get a response from the login flow")]
    NoResponse,
    #[error("There is no refresh token available for configuration {0}")]
    NoRefreshTokenForConfig(String),
    #[error("Could not read access token from {0}. Is the configuration corrupt?")]
    CouldNotReadConfigCorrupt(String),
    #[error("OpenID error: {0}")]
    OpenIdError(String),
}

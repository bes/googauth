use openidconnect::ClaimsVerificationError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LibError {
    #[error("No such configuration: {0}")]
    NoSuchConfiguration(String),
    #[error("Can not find home directory")]
    HomeDirectoryNotFound,
    #[error("Configs directory {0} is not a directory")]
    ConfigsDirectoryNotADirectory(PathBuf),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Filename error")]
    FilenameError,
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),
    #[error(
        "The state sent to the server, and the state received from the server do not match - this may be a sign of a CSRF attack"
    )]
    TokenCsrfError,
    #[error("No ID token present")]
    NoIdToken,
    #[error("No refresh token present")]
    NoRefreshToken,
    #[error("Could not refresh token")]
    CouldNotRefreshToken,
    #[error("Could not read claims")]
    CouldNotReadClaims(#[source] ClaimsVerificationError),
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
    #[error("Failed to access token endpoint")]
    TokenEndpointError(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("No local port in redirect URL")]
    NoRedirectPortError,
    #[error("Could not listen for the browser redirect on port {0}: {1}")]
    RedirectListenerError(u16, #[source] std::io::Error),
    #[error("Google did not authorize the sign in: {0}")]
    AuthorizationError(String),
    #[error("The browser redirect did not contain an authorization code")]
    NoAuthorizationCode,
    #[error(
        "Invalid configuration name {0:?}. A configuration name must be a file name, not a path"
    )]
    InvalidConfigName(String),
}

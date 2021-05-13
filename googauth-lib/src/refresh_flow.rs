use crate::config_file::{ConfigBasePath, ConfigFile, Token};
use crate::errors::LibError;
use openidconnect::core::{CoreClient, CoreIdTokenVerifier, CoreProviderMetadata};
use openidconnect::reqwest::http_client;
use openidconnect::{
    ClientId, ClientSecret, IssuerUrl, OAuth2TokenResponse, RefreshToken, Scope, TokenResponse,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn refresh_google_login(
    config: &mut ConfigFile,
    config_base_path: &ConfigBasePath,
) -> Result<(), LibError> {
    let google_client_id = ClientId::new(config.client_id.to_string());
    let google_client_secret = ClientSecret::new(config.client_secret.to_string());
    let issuer_url =
        IssuerUrl::new("https://accounts.google.com".to_string()).expect("Invalid issuer URL");

    // Fetch Google's OpenID Connect discovery document.
    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, http_client)
        .map_err(|_| LibError::OpenIdError("Failed to discover OpenID Provider".to_string()))?;

    let refresh_token = match &config.refresh_token {
        Some(refresh_token) => RefreshToken::new(refresh_token.to_string()),
        None => {
            return Err(LibError::NoRefreshTokenForConfig(config.name.clone()));
        }
    };

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        google_client_id,
        Some(google_client_secret),
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut refresh_token_request = client.exchange_refresh_token(&refresh_token);

    for scope in &config.scopes {
        refresh_token_request = refresh_token_request.add_scope(Scope::new(scope.to_string()));
    }

    let refresh_token_result = refresh_token_request.request(http_client);

    let token_response = match refresh_token_result {
        Ok(rt) => rt,
        Err(_) => {
            return Err(LibError::CouldNotRefreshToken);
        }
    };

    let access_token = token_response.access_token().secret().to_string();
    let access_token_exp = match token_response.expires_in() {
        None => 0,
        Some(expires_in) => now + expires_in.as_secs(),
    };
    config.access_token = Some(Token::new(access_token, access_token_exp));

    let id_token = token_response.id_token().ok_or(LibError::NoIdToken)?;
    let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    let id_token_claims = match id_token.claims(&id_token_verifier, |_: Option<&_>| Ok(())) {
        Ok(claims) => claims,
        Err(e) => {
            println!("ERR {:?}", e);
            return Err(LibError::CouldNotReadClaims);
        }
    };
    let id_token_exp = id_token_claims.expiration().timestamp() as u64;
    config.id_token = Some(Token::new(id_token.to_string(), id_token_exp));

    config.save_config(config_base_path)
}

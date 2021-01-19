use googauth_lib::{ConfigFile, Token};
use super::errors::handle_error;
use openidconnect::core::{CoreClient, CoreIdTokenVerifier, CoreProviderMetadata};
use openidconnect::reqwest::http_client;
use openidconnect::{
    ClientId, ClientSecret, IssuerUrl, OAuth2TokenResponse, RefreshToken,
    Scope,
};
use simple_error::SimpleError;
use std::time::{SystemTime, UNIX_EPOCH};
use openidconnect::TokenResponse;

pub fn refresh_google_login(config: &mut ConfigFile) -> Result<(), SimpleError> {
    let google_client_id = ClientId::new(config.client_id.to_string());
    let google_client_secret = ClientSecret::new(config.client_secret.to_string());
    let issuer_url =
        IssuerUrl::new("https://accounts.google.com".to_string()).expect("Invalid issuer URL");

    // Fetch Google's OpenID Connect discovery document.
    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to discover OpenID Provider");
            unreachable!();
        });

    let refresh_token = match &config.refresh_token {
        Some(refresh_token) => RefreshToken::new(refresh_token.to_string()),
        None => {
            return Err(SimpleError::new(format!(
                "There is no refresh token available for configuration {}",
                &config.name
            )));
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
            return Err(SimpleError::new("Could not refresh token"));
        }
    };

    let access_token = token_response.access_token().secret().to_string();
    let access_token_exp = match token_response.expires_in() {
        None => 0,
        Some(expires_in) => now + expires_in.as_secs(),
    };
    config.access_token = Some(Token::new(access_token.to_string(), access_token_exp));

    let id_token = match token_response.id_token() {
        Some(token) => token,
        None => {
            return Err(SimpleError::new("No id token available"));
        }
    };
    let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    let id_token_claims = match id_token.claims(&id_token_verifier, |_: Option<&_>| Ok(())) {
        Ok(claims) => claims,
        Err(e) => {
            println!("ERR {}", e);
            return Err(SimpleError::new("Could not read id token claims"));
        }
    };
    let id_token_exp = id_token_claims.expiration().timestamp() as u64;
    config.id_token = Some(Token::new(id_token.to_string(), id_token_exp));

    return config.save_config();
}

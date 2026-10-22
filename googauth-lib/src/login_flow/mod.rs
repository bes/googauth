use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config_file::{ConfigBasePath, ConfigFile, Token};
use crate::errors::LibError;
use openidconnect::core::{
    CoreAuthPrompt, CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata,
    CoreResponseType,
};
use openidconnect::{
    AsyncHttpClient, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use url::Url;

#[cfg(test)]
mod tests;

/// Signs in to Google in the browser and saves the tokens in the config.
///
/// The `http_client` must not follow redirects, since following redirects opens
/// the client up to SSRF vulnerabilities.
pub async fn google_login<C: for<'c> AsyncHttpClient<'c>>(
    config: &mut ConfigFile,
    config_base_path: &ConfigBasePath,
    http_client: &C,
) -> Result<(), LibError> {
    let google_client_id = ClientId::new(config.client_id.to_string());
    let google_client_secret = ClientSecret::new(config.client_secret.to_string());
    let issuer_url = IssuerUrl::new("https://accounts.google.com".to_string())?;
    let redirect_url = Url::parse(&config.redirect_url)?;

    let port = match redirect_url.port() {
        Some(port) => port,
        None => {
            return Err(LibError::NoRedirectPortError);
        }
    };

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .map_err(|err| LibError::RedirectListenerError(port, err))?;

    // Fetch Google's OpenID Connect discovery document.
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, http_client)
        .await
        .map_err(|_| LibError::OpenIdError("Failed to discover OpenID Provider".to_string()))?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        google_client_id,
        Some(google_client_secret),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url.to_string())?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let request = client.authorize_url(
        AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );

    let request = request
        .add_extra_param("access_type", "offline")
        .add_prompt(CoreAuthPrompt::Consent)
        .set_pkce_challenge(pkce_challenge);

    let request = config.scopes.iter().fold(request, |request, scope| {
        request.add_scope(Scope::new(scope.to_string()))
    });

    let (authorize_url, csrf_state, nonce) = request.url();

    let authorize_url_string = authorize_url.to_string();

    webbrowser::open(&authorize_url_string)?;

    eprintln!(
        "If the web browser did not open automatically, you can open this URL in your browser:\n{}\n",
        authorize_url_string
    );

    eprintln!("Waiting for the browser to sign you in...");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if let Some(mut stream) = listener.incoming().flatten().next() {
        let redirect = read_redirect(&stream, &csrf_state);

        let (status, message) = match redirect {
            Ok(_) => ("200 OK", "Go back to your terminal :)"),
            Err(_) => (
                "400 Bad Request",
                "Could not sign in, go back to your terminal for details",
            ),
        };
        let response = format!(
            "HTTP/1.1 {}\r\ncontent-length: {}\r\n\r\n{}",
            status,
            message.len(),
            message
        );
        let written = stream.write_all(response.as_bytes());

        let code = redirect?;
        written?;

        // Exchange the code with a token.
        let token_response = client
            .exchange_code(code)
            .map_err(|openid_err| LibError::OpenIdError(openid_err.to_string()))?
            .set_pkce_verifier(pkce_verifier)
            .request_async(http_client)
            .await
            .map_err(|e| {
                eprintln!("{:?}", e);
                LibError::OpenIdError("Failed to access token endpoint".to_string())
            })?;

        let access_token_expires = match token_response.expires_in() {
            None => 0,
            Some(expires_in) => now + expires_in.as_secs(),
        };

        let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
        let id_token_claims: &CoreIdTokenClaims = token_response
            .extra_fields()
            .id_token()
            .ok_or(LibError::NoIdToken)?
            .claims(&id_token_verifier, &nonce)
            .map_err(|_| LibError::OpenIdError("Failed to verify ID token".to_string()))?;

        let id_token = token_response
            .id_token()
            .ok_or(LibError::NoIdToken)?
            .to_string();
        let refresh_token = token_response
            .refresh_token()
            .ok_or(LibError::NoRefreshToken)?;
        let access_token = token_response.access_token().secret().to_string();

        let scopes = token_response.scopes().ok_or(LibError::NoScopes)?;

        config.scopes = scopes.iter().map(|scope| scope.to_string()).collect();
        config.refresh_token = Some(refresh_token.secret().to_string());
        config.id_token = Some(Token::new(
            id_token,
            id_token_claims.expiration().timestamp() as u64,
        ));
        config.access_token = Some(Token::new(access_token, access_token_expires));

        return config.save_config(config_base_path);
    }

    Err(LibError::NoResponse)
}

fn read_redirect(
    request: impl Read,
    csrf_state: &CsrfToken,
) -> Result<AuthorizationCode, LibError> {
    let mut request_line = String::new();
    BufReader::new(request).read_line(&mut request_line)?;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or(LibError::NoAuthorizationCode)?;
    let url = Url::parse(&("http://localhost".to_string() + path))?;
    let query_value = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };

    if let Some(error) = query_value("error") {
        return Err(LibError::AuthorizationError(error));
    }
    let code = query_value("code").ok_or(LibError::NoAuthorizationCode)?;
    if query_value("state").as_deref() != Some(csrf_state.secret().as_str()) {
        return Err(LibError::TokenCsrfError);
    }

    Ok(AuthorizationCode::new(code))
}

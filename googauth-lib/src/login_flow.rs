use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config_file::{ConfigBasePath, ConfigFile, Token};
use crate::errors::LibError;
use openidconnect::core::{
    CoreAuthPrompt, CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata,
    CoreResponseType,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use url::Url;

pub async fn google_login(
    config: &mut ConfigFile,
    config_base_path: &ConfigBasePath,
) -> Result<(), LibError> {
    let google_client_id = ClientId::new(config.client_id.to_string());
    let google_client_secret = ClientSecret::new(config.client_secret.to_string());
    let issuer_url = IssuerUrl::new("https://accounts.google.com".to_string())?;
    let redirect_url = Url::parse(&config.redirect_url)?;

    // Fetch Google's OpenID Connect discovery document.
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client)
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

    println!(
        "If the web browser did not open automatically, you can open this URL in your browser:\n{}\n",
        &authorize_url_string
    );

    println!("Waiting for the browser to sign you in...");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            let state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();

            if state.secret() != csrf_state.secret() {
                return Err(LibError::TokenCsrfError);
            }

            // Exchange the code with a token.
            let token_response = client
                .exchange_code(code)
                .set_pkce_verifier(pkce_verifier)
                .request_async(async_http_client)
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
    }

    Err(LibError::NoResponse)
}

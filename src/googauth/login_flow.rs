use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use webbrowser;

use super::config_file::{ConfigFile, Token};
use super::errors::handle_error;
use openidconnect::core::{
    CoreAuthPrompt, CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata,
    CoreResponseType,
};
use openidconnect::reqwest::http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, Scope, TokenResponse,
};
use simple_error::SimpleError;
use url::Url;

pub fn google_login(config: &mut ConfigFile) -> Result<(), SimpleError> {
    let google_client_id = ClientId::new(config.client_id.to_string());
    let google_client_secret = ClientSecret::new(config.client_secret.to_string());
    let issuer_url = match IssuerUrl::new("https://accounts.google.com".to_string()) {
        Ok(issuer_url) => issuer_url,
        Err(e) => {
            return Err(SimpleError::with("Invalid issuer URL", e));
        }
    };
    let redirect_url = match Url::parse(&config.redirect_url) {
        Ok(redirect_url) => redirect_url,
        Err(e) => {
            return Err(SimpleError::with("Invalid redirect URL", e));
        }
    };

    // Fetch Google's OpenID Connect discovery document.
    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to discover OpenID Provider");
            unreachable!();
        });

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        google_client_id,
        Some(google_client_secret),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url.to_string()).map_err(|e| SimpleError::with("Could not convert redirect URL to string", e))?);

    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // This example is requesting access to the "calendar" features and the user's profile.
        .add_extra_param("access_type", "offline")
        .add_prompt(CoreAuthPrompt::Consent)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    let authorize_url_string = authorize_url.to_string();

    match webbrowser::open(&authorize_url_string) {
        Ok(_) => {}
        Err(e) => return Err(SimpleError::from(e)),
    }

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
                return Err(SimpleError::new("The state sent to the server, and the state received from the server do not match - this may be a sign of a CSRF attack"));
            }

            // Exchange the code with a token.
            let token_response = client
                .exchange_code(code)
                .request(http_client)
                .unwrap_or_else(|err| {
                    handle_error(&err, "Failed to access token endpoint");
                    unreachable!();
                });

            let access_token_expires = match token_response.expires_in() {
                None => 0,
                Some(expires_in) => now + expires_in.as_secs(),
            };

            let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
            let id_token_claims: &CoreIdTokenClaims = token_response
                .extra_fields()
                .id_token().ok_or(SimpleError::new("No ID token present in extra fields"))?
                .claims(&id_token_verifier, &nonce)
                .unwrap_or_else(|err| {
                    handle_error(&err, "Failed to verify ID token");
                    unreachable!();
                });

            let id_token = token_response.id_token().ok_or(SimpleError::new("No ID token present"))?.to_string();
            let refresh_token = match token_response.refresh_token() {
                Some(refresh_token) => refresh_token,
                None => {
                    return Err(SimpleError::new(
                        "There was no refresh token in the response",
                    ));
                }
            };
            let access_token = token_response.access_token().secret().to_string();

            let scopes = match token_response.scopes() {
                Some(scopes) => scopes,
                None => {
                    return Err(SimpleError::new("There were no scopes in the response"));
                }
            };

            config.scopes = scopes.into_iter().map(|scope| scope.to_string()).collect();
            config.refresh_token = Some(refresh_token.secret().to_string());
            config.id_token = Some(Token::new(
                id_token,
                id_token_claims.expiration().timestamp() as u64,
            ));
            config.access_token = Some(Token::new(access_token, access_token_expires));

            return config.save_config();
        }
    }

    Err(SimpleError::new(
        "Could not get a response from the login flow",
    ))
}

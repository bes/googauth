use super::read_redirect;
use crate::errors::LibError;
use openidconnect::CsrfToken;

fn csrf_state() -> CsrfToken {
    CsrfToken::new("expected-state".to_string())
}

fn read_code(request: &str) -> Result<String, LibError> {
    read_redirect(request.as_bytes(), &csrf_state()).map(|code| code.secret().to_string())
}

#[test]
fn returns_the_code_when_the_state_matches() {
    let request = "GET /?state=expected-state&code=4%2F0Ab HTTP/1.1\r\nHost: localhost\r\n\r\n";

    assert_eq!(read_code(request).unwrap(), "4/0Ab");
}

#[test]
fn returns_the_error_from_google() {
    for request in [
        "GET /?error=access_denied&state=expected-state HTTP/1.1\r\n",
        "GET /?error=access_denied HTTP/1.1\r\n",
        "GET /?error=access_denied&code=abc&state=expected-state HTTP/1.1\r\n",
    ] {
        assert!(
            matches!(
                read_code(request),
                Err(LibError::AuthorizationError(error)) if error == "access_denied"
            ),
            "{request:?}"
        );
    }
}

#[test]
fn fails_without_a_code() {
    for request in [
        "",
        "\r\n",
        "GET\r\n",
        "GET / HTTP/1.1\r\n",
        "GET /favicon.ico HTTP/1.1\r\n",
        "GET /?state=expected-state HTTP/1.1\r\n",
    ] {
        assert!(
            matches!(read_code(request), Err(LibError::NoAuthorizationCode)),
            "{request:?}"
        );
    }
}

#[test]
fn fails_when_the_state_does_not_match() {
    for request in [
        "GET /?code=abc HTTP/1.1\r\n",
        "GET /?code=abc&state= HTTP/1.1\r\n",
        "GET /?code=abc&state=other-state HTTP/1.1\r\n",
    ] {
        assert!(
            matches!(read_code(request), Err(LibError::TokenCsrfError)),
            "{request:?}"
        );
    }
}

#[test]
fn fails_on_a_malformed_request() {
    assert!(matches!(
        read_redirect(b"GET /?code=\xff HTTP/1.1\r\n".as_slice(), &csrf_state()),
        Err(LibError::IoError(_))
    ));
    assert!(matches!(
        read_code("GET @[ HTTP/1.1\r\n"),
        Err(LibError::UrlError(_))
    ));
}

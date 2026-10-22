use super::{parse_redirect, read_request_line, receive_redirect};
use crate::errors::LibError;
use openidconnect::CsrfToken;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn csrf_state() -> CsrfToken {
    CsrfToken::new("expected-state".to_string())
}

fn parse_code(request_line: &str) -> Result<String, LibError> {
    parse_redirect(request_line, &csrf_state()).map(|code| code.secret().to_string())
}

/// Sends a request to the redirect server the way a browser would, and returns the response.
fn send_request(address: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

struct FailingRead(ErrorKind);

impl Read for FailingRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(self.0))
    }
}

#[test]
fn returns_the_code_when_the_state_matches() {
    assert_eq!(
        parse_code("GET /?state=expected-state&code=4%2F0Ab HTTP/1.1\r\n").unwrap(),
        "4/0Ab"
    );
}

#[test]
fn returns_the_error_from_google() {
    for request_line in [
        "GET /?error=access_denied&state=expected-state HTTP/1.1\r\n",
        "GET /?error=access_denied HTTP/1.1\r\n",
        "GET /?error=access_denied&code=abc&state=expected-state HTTP/1.1\r\n",
    ] {
        assert!(
            matches!(
                parse_code(request_line),
                Err(LibError::AuthorizationError(error)) if error == "access_denied"
            ),
            "{request_line:?}"
        );
    }
}

#[test]
fn fails_without_a_code() {
    for request_line in [
        "\r\n",
        "GET\r\n",
        "GET / HTTP/1.1\r\n",
        "GET /favicon.ico HTTP/1.1\r\n",
        "GET /?state=expected-state HTTP/1.1\r\n",
    ] {
        assert!(
            matches!(parse_code(request_line), Err(LibError::NoAuthorizationCode)),
            "{request_line:?}"
        );
    }
}

#[test]
fn fails_when_the_state_does_not_match() {
    for request_line in [
        "GET /?code=abc HTTP/1.1\r\n",
        "GET /?code=abc&state= HTTP/1.1\r\n",
        "GET /?code=abc&state=other-state HTTP/1.1\r\n",
    ] {
        assert!(
            matches!(parse_code(request_line), Err(LibError::TokenCsrfError)),
            "{request_line:?}"
        );
    }
}

#[test]
fn fails_on_a_malformed_request_line() {
    assert!(matches!(
        parse_code("GET @[ HTTP/1.1\r\n"),
        Err(LibError::UrlError(_))
    ));
}

#[test]
fn reads_only_the_request_line() {
    let request = b"GET /?code=abc HTTP/1.1\r\nHost: localhost\r\n\r\n";

    assert_eq!(
        read_request_line(request.as_slice()).unwrap().as_deref(),
        Some("GET /?code=abc HTTP/1.1\r\n")
    );
}

#[test]
fn has_no_request_line_when_the_connection_closes_or_times_out() {
    assert!(read_request_line(b"".as_slice()).unwrap().is_none());
    for kind in [ErrorKind::WouldBlock, ErrorKind::TimedOut] {
        assert!(
            read_request_line(FailingRead(kind)).unwrap().is_none(),
            "{kind:?}"
        );
    }
}

#[test]
fn fails_on_a_request_line_that_is_not_utf8() {
    assert!(matches!(
        read_request_line(b"GET /?code=\xff HTTP/1.1\r\n".as_slice()),
        Err(LibError::IoError(_))
    ));
}

#[test]
fn ignores_connections_that_send_no_request_line() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let browser = thread::spawn(move || {
        drop(TcpStream::connect(address).unwrap());
        let _silent = TcpStream::connect(address).unwrap();
        send_request(
            address,
            "GET /?code=abc&state=expected-state HTTP/1.1\r\n\r\n",
        )
    });

    let code = receive_redirect(&listener, &csrf_state(), Duration::from_millis(100)).unwrap();

    assert_eq!(code.secret(), "abc");
    let response = browser.join().unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        response.ends_with("Go back to your terminal :)"),
        "{response}"
    );
}

#[test]
fn tells_the_browser_when_the_sign_in_failed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let browser = thread::spawn(move || {
        send_request(
            address,
            "GET /?error=access_denied&state=expected-state HTTP/1.1\r\n\r\n",
        )
    });

    let result = receive_redirect(&listener, &csrf_state(), Duration::from_secs(5));

    assert!(matches!(
        result,
        Err(LibError::AuthorizationError(error)) if error == "access_denied"
    ));
    let response = browser.join().unwrap();
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(
        response.ends_with("go back to your terminal for details"),
        "{response}"
    );
}

use super::format_error;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
struct ChainedError {
    message: &'static str,
    source: Option<Box<ChainedError>>,
}

impl ChainedError {
    fn chain(messages: &[&'static str]) -> ChainedError {
        let (message, causes) = messages.split_first().unwrap();
        ChainedError {
            message,
            source: if causes.is_empty() {
                None
            } else {
                Some(Box::new(ChainedError::chain(causes)))
            },
        }
    }
}

impl fmt::Display for ChainedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl Error for ChainedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[test]
fn formats_an_error_without_a_cause() {
    let error = ChainedError::chain(&["Could not read claims"]);

    assert_eq!(format_error(&error), "Error: Could not read claims\n");
}

#[test]
fn formats_every_cause() {
    let error = ChainedError::chain(&[
        "Failed to access token endpoint",
        "Request failed",
        "error sending request for url (https://oauth2.googleapis.com/token)",
    ]);

    assert_eq!(
        format_error(&error),
        "Error: Failed to access token endpoint\n\
         Caused by: Request failed\n\
         Caused by: error sending request for url (https://oauth2.googleapis.com/token)\n"
    );
}

#[test]
fn skips_causes_that_are_already_in_the_message() {
    let error = ChainedError::chain(&[
        "I/O error: No such file or directory (os error 2)",
        "No such file or directory (os error 2)",
        "the disk was removed",
    ]);

    assert_eq!(
        format_error(&error),
        "Error: I/O error: No such file or directory (os error 2)\n\
         Caused by: the disk was removed\n"
    );
}

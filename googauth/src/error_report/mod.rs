use std::error::Error;
use std::process::exit;

#[cfg(test)]
mod tests;

const FAILURE: i32 = 1;

pub fn exit_with_error(error: &dyn Error) -> ! {
    eprint!("{}", format_error(error));
    exit(FAILURE)
}

pub fn exit_with_message(message: &str) -> ! {
    eprintln!("Error: {message}");
    exit(FAILURE)
}

fn format_error(error: &dyn Error) -> String {
    let mut report = format!("Error: {error}\n");
    let mut last_message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let message = cause.to_string();
        if !last_message.contains(&message) {
            report.push_str(&format!("Caused by: {message}\n"));
            last_message = message;
        }
        source = cause.source();
    }
    report
}

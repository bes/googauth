use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use googauth_lib::{ConfigBasePath, ConfigFile, Token};

/// Creates an empty HOME directory for a test, so that the real ~/.googauth is never touched.
fn temp_home(test_name: &str) -> PathBuf {
    let home = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test_name);
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    home
}

fn config_base_path(home: &Path) -> ConfigBasePath {
    ConfigBasePath::from(home.join(".googauth"))
}

/// Runs googauth with the given HOME, ignoring any googauth environment variables set by the caller.
fn googauth(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_googauth"));
    command
        .env("HOME", home)
        .env_remove("CLIENT_ID")
        .env_remove("CLIENT_SECRET")
        .env_remove("SCOPES")
        .env_remove("REDIRECT");
    command
}

fn run(command: &mut Command) -> (Output, String, String) {
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output, stdout, stderr)
}

/// Saves a config with tokens that never expire, so reading them does not require a refresh.
fn save_signed_in_config(home: &Path, name: &str) {
    let mut config = ConfigFile::new(
        name,
        "client-id",
        "client-secret",
        &["openid".to_string(), "email".to_string()],
        "http://localhost:8080/",
    );
    config.access_token = Some(Token::new(format!("{}-access-token", name), u64::MAX));
    config.id_token = Some(Token::new(format!("{}-id-token", name), u64::MAX));
    config.save_config(&config_base_path(home)).unwrap();
}

#[test]
fn prints_version() {
    let home = temp_home("prints_version");
    let (output, stdout, _) = run(googauth(&home).arg("--version"));

    assert!(output.status.success());
    assert_eq!(stdout, format!("googauth {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_subcommands() {
    let home = temp_home("help_lists_subcommands");
    let (output, stdout, _) = run(googauth(&home).arg("--help"));

    assert!(output.status.success());
    for subcommand in ["list", "login", "accesstoken", "idtoken"] {
        assert!(
            stdout.contains(subcommand),
            "missing {}:\n{}",
            subcommand,
            stdout
        );
    }
}

#[test]
fn login_help_lists_options_and_env_vars() {
    let home = temp_home("login_help_lists_options_and_env_vars");
    let (output, stdout, _) = run(googauth(&home).args(["login", "--help"]));

    assert!(output.status.success());
    for expected in [
        "<CONFIG NAME>",
        "--id",
        "CLIENT_ID",
        "--secret",
        "CLIENT_SECRET",
        "--scopes",
        "SCOPES",
        "--redirect",
        "REDIRECT",
        "http://localhost:8080/",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {}:\n{}",
            expected,
            stdout
        );
    }
}

#[test]
fn no_subcommand_prints_help_and_fails() {
    let home = temp_home("no_subcommand_prints_help_and_fails");
    let (output, stdout, stderr) = run(&mut googauth(&home));

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout, "");
    assert!(stderr.contains("Usage:"), "{}", stderr);
}

#[test]
fn list_without_configs() {
    let home = temp_home("list_without_configs");
    let (output, stdout, stderr) = run(googauth(&home).arg("list"));

    assert!(output.status.success());
    assert_eq!(stdout, "");
    assert_eq!(stderr, "No configs available\n");

    fs::create_dir(home.join(".googauth")).unwrap();
    let (output, stdout, stderr) = run(googauth(&home).arg("list"));

    assert!(output.status.success());
    assert_eq!(stdout, "");
    assert_eq!(stderr, "No configs available\n");
}

#[test]
fn list_fails_when_configs_path_is_a_file() {
    let home = temp_home("list_fails_when_configs_path_is_a_file");
    fs::write(home.join(".googauth"), "").unwrap();

    let (output, stdout, stderr) = run(googauth(&home).arg("list"));

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout, "");
    assert!(
        stderr.starts_with("Error: Configs directory "),
        "{}",
        stderr
    );
}

#[test]
fn list_shows_saved_configs() {
    let home = temp_home("list_shows_saved_configs");
    save_signed_in_config(&home, "work");
    save_signed_in_config(&home, "personal");

    let (output, stdout, _) = run(googauth(&home).arg("list"));

    assert!(output.status.success());
    let mut lines: Vec<_> = stdout.lines().map(str::trim_end).collect();
    lines.sort();
    assert_eq!(
        lines,
        [
            format!("{: <25} | openid, email", "personal"),
            format!("{: <25} | openid, email", "work"),
        ]
    );
}

#[test]
fn accesstoken_prints_unexpired_token() {
    let home = temp_home("accesstoken_prints_unexpired_token");
    save_signed_in_config(&home, "work");

    let (output, stdout, _) = run(googauth(&home).args(["accesstoken", "work"]));

    assert!(output.status.success());
    assert_eq!(stdout, "work-access-token\n");
}

#[test]
fn idtoken_prints_unexpired_token() {
    let home = temp_home("idtoken_prints_unexpired_token");
    save_signed_in_config(&home, "work");

    let (output, stdout, _) = run(googauth(&home).args(["idtoken", "work"]));

    assert!(output.status.success());
    assert_eq!(stdout, "work-id-token\n");
}

/// Runs both token subcommands, which should fail the same way, and returns their error output.
fn token_errors(home: &Path, config_name: &str) -> String {
    let errors: Vec<_> = ["accesstoken", "idtoken"]
        .into_iter()
        .map(|subcommand| {
            let (output, stdout, stderr) = run(googauth(home).args([subcommand, config_name]));

            assert_eq!(output.status.code(), Some(1), "{}", subcommand);
            assert_eq!(stdout, "", "{}", subcommand);
            stderr
        })
        .collect();

    assert_eq!(errors[0], errors[1]);
    errors[0].clone()
}

#[test]
fn tokens_for_unknown_config_fail() {
    let home = temp_home("tokens_for_unknown_config_fail");

    let stderr = token_errors(&home, "missing");
    assert!(stderr.starts_with("Error: I/O error: "), "{}", stderr);
}

#[test]
fn tokens_for_corrupt_config_fail() {
    let home = temp_home("tokens_for_corrupt_config_fail");
    fs::create_dir(home.join(".googauth")).unwrap();
    fs::write(home.join(".googauth/corrupt"), "not json").unwrap();

    let stderr = token_errors(&home, "corrupt");
    assert!(stderr.starts_with("Error: JSON error: "), "{}", stderr);
}

#[test]
fn config_name_is_required() {
    let home = temp_home("config_name_is_required");

    for subcommand in ["login", "accesstoken", "idtoken"] {
        let (output, _, stderr) = run(googauth(&home).arg(subcommand));

        assert_eq!(output.status.code(), Some(2), "{}", subcommand);
        assert!(
            stderr.contains("<CONFIG NAME>"),
            "{}: {}",
            subcommand,
            stderr
        );
    }
}

// The login tests use an invalid redirect URL. The new config is saved before the login flow
// starts, and the login flow fails on the redirect URL before contacting Google or opening a
// browser, so the saved config can be checked without signing in.

#[test]
fn login_saves_config_from_arguments() {
    let home = temp_home("login_saves_config_from_arguments");
    let (output, stdout, stderr) = run(googauth(&home).args([
        "login",
        "work",
        "--id",
        "my-id",
        "-s",
        "my-secret",
        "--scopes",
        "openid",
        "email",
        "-o",
        "profile,https://www.googleapis.com/auth/cloud-platform",
        "-r",
        "not-a-url",
    ]));

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout, "");
    assert!(stderr.starts_with("Saved configuration to "), "{}", stderr);
    assert!(stderr.contains("URL parse error"), "{}", stderr);

    let config = ConfigFile::read_config("work", &config_base_path(&home)).unwrap();
    assert_eq!(config.name, "work");
    assert_eq!(config.client_id, "my-id");
    assert_eq!(config.client_secret, "my-secret");
    assert_eq!(
        config.scopes,
        [
            "openid",
            "email",
            "profile",
            "https://www.googleapis.com/auth/cloud-platform"
        ]
    );
    assert_eq!(config.redirect_url, "not-a-url");
    assert!(config.refresh_token.is_none());

    let config_path = ConfigFile::config_file("work", &config_base_path(&home)).unwrap();
    let mode = fs::metadata(config_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "the config file holds secrets");
}

#[test]
fn login_reads_options_from_env_vars() {
    let home = temp_home("login_reads_options_from_env_vars");
    let (output, stdout, stderr) = run(googauth(&home)
        .args(["login", "work"])
        .env("CLIENT_ID", "env-id")
        .env("CLIENT_SECRET", "env-secret")
        .env("SCOPES", "openid,email")
        .env("REDIRECT", "not-a-url"));

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout, "");
    assert!(stderr.contains("URL parse error"), "{}", stderr);

    let config = ConfigFile::read_config("work", &config_base_path(&home)).unwrap();
    assert_eq!(config.client_id, "env-id");
    assert_eq!(config.client_secret, "env-secret");
    assert_eq!(config.scopes, ["openid", "email"]);
    assert_eq!(config.redirect_url, "not-a-url");
}

#[test]
fn login_requires_client_id_secret_and_scopes() {
    let home = temp_home("login_requires_client_id_secret_and_scopes");

    for (args, error) in [
        (vec!["-s", "my-secret", "-o", "openid"], "a client id"),
        (vec!["-i", "my-id", "-o", "openid"], "a client secret"),
        (vec!["-i", "my-id", "-s", "my-secret"], "at least one scope"),
    ] {
        let (output, _, stderr) = run(googauth(&home).args(["login", "work"]).args(&args));

        assert_eq!(output.status.code(), Some(1), "{:?}", args);
        assert_eq!(
            stderr,
            format!(
                "Error: You must specify {} for the configuration work\n",
                error
            ),
            "{:?}",
            args
        );
    }
    assert!(!home.join(".googauth").exists());
}

#[test]
fn login_rejects_empty_scope() {
    let home = temp_home("login_rejects_empty_scope");
    let (output, _, stderr) = run(googauth(&home).args([
        "login",
        "work",
        "-i",
        "my-id",
        "-s",
        "my-secret",
        "-o",
        "openid,,email",
    ]));

    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("You must specify at least one scope"),
        "{}",
        stderr
    );
    assert!(!home.join(".googauth").exists());
}

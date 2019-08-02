#[macro_use]
extern crate simple_error;

extern crate base64;
extern crate env_logger;
extern crate failure;
extern crate openidconnect;
extern crate rand;
extern crate serde_derive;
extern crate serde_json;
extern crate url;

use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{App, Arg, SubCommand};

mod googauth;

use crate::googauth::config_file::{ConfigFile, Token};
use crate::googauth::login_flow::google_login;
use crate::googauth::refresh_flow::refresh_google_login;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    env_logger::init();

    let config_name_arg = Arg::with_name("config")
        .value_name("CONFIG NAME")
        .required(true)
        .index(1)
        .help("The configuration name")
        .long_help("The configuration will cache the refresh token and other values to avoid reauthorization on reuse");

    let app = App::new("googauth")
        .version(VERSION)
        .about("Request and store Google OpenID (OAuth) tokens")
        .subcommand(SubCommand::with_name("list")
            .help("List all the current profiles")
        )
        .subcommand(SubCommand::with_name("login")
            .arg(config_name_arg.clone())
            .arg(
                Arg::with_name("clientid")
                    .env("CLIENT_ID")
                    .long("id")
                    .short("i")
                    .takes_value(true)
                    .help("The client id")
                    .long_help("The client id. Can be created at http://console.developers.google.com"),
            )
            .arg(
                Arg::with_name("secret")
                    .env("CLIENT_SECRET")
                    .long("secret")
                    .short("s")
                    .takes_value(true)
                    .help("The client secret")
                    .long_help("The client secret. Can be created at http://console.developers.google.com"),
            )
            .arg(
                Arg::with_name("scopes")
                    .env("SCOPES")
                    .long("scopes")
                    .short("o")
                    .takes_value(true)
                    .multiple(true)
                    .use_delimiter(true)
                    .validator(|scopes| {
                        if scopes.len() > 0 {
                            return Ok(());
                        }
                        Err(String::from("You must specify at least one scope"))
                    })
                    .help("The scopes to request")
                    .long_help("One or more scopes to request from the provider."),
            )
            .arg(
                Arg::with_name("redirect")
                    .env("REDIRECT")
                    .long("redirect")
                    .short("r")
                    .takes_value(true)
                    .default_value("http://localhost:8080/")
                    .help("OAuth Redirect URL")
            )
        )
        .subcommand(SubCommand::with_name("accesstoken")
            .arg(config_name_arg.clone())
        )
        .subcommand(SubCommand::with_name("idtoken")
            .arg(config_name_arg.clone())
        );

    let matches = app.get_matches();

    match matches.subcommand() {
        ("list", Some(_)) => {
            let config_list = match ConfigFile::list_configs() {
                Some(config_list) => config_list,
                None => {
                    print_success_and_exit("No configs available");
                    unreachable!()
                }
            };
            for config_name in config_list {
                println!("{}", &config_name);
            }
        }
        ("login", Some(matches)) => {
            let config_name = match matches.value_of("config") {
                Some(config_name) => config_name,
                None => {
                    print_error_and_exit("You must specify an configuration name");
                    unreachable!()
                }
            };
            let mut config = match ConfigFile::read_config(&config_name) {
                None => {
                    let client_id = match matches.value_of("clientid") {
                        Some(client_id) => client_id,
                        None => {
                            print_error_and_exit(&format!(
                                "You must specify a client id for the configuration {}",
                                &config_name
                            ));
                            unreachable!()
                        }
                    };
                    let client_secret = match matches.value_of("secret") {
                        Some(client_secret) => client_secret,
                        None => {
                            print_error_and_exit(&format!(
                                "You must specify a client secret for the configuration {}",
                                &config_name
                            ));
                            unreachable!()
                        }
                    };
                    let scopes = match matches.values_of_lossy("scopes") {
                        Some(scopes) => scopes,
                        None => {
                            print_error_and_exit(&format!(
                                "You must specify at least one scope for the configuration {}",
                                &config_name
                            ));
                            unreachable!()
                        }
                    };
                    let redirect_url = match matches.value_of("redirect") {
                        Some(redirect_url) => redirect_url,
                        None => {
                            print_error_and_exit(&format!(
                                "You must specify a redirect URL for the configuration {}",
                                &config_name
                            ));
                            unreachable!()
                        }
                    };
                    let new_config = ConfigFile::new(
                        &config_name,
                        client_id,
                        client_secret,
                        &scopes,
                        redirect_url,
                    );

                    match new_config.save_config() {
                        Ok(_) => (),
                        Err(e) => {
                            print_error_and_exit(&e.to_string());
                            unreachable!()
                        }
                    }

                    match ConfigFile::config_file(&config_name) {
                        Some(config) => match config.to_str() {
                            Some(config_str) => println!("Saved configuration to {}", config_str),
                            None => {}
                        },
                        None => {}
                    }

                    new_config
                }
                Some(mut config) => {
                    match matches.value_of("clientid") {
                        Some(client_id) => {
                            config.client_id = client_id.to_string();
                        }
                        None => {}
                    }
                    match matches.value_of("secret") {
                        Some(client_secret) => {
                            config.client_secret = client_secret.to_string();
                        }
                        None => {}
                    }
                    match matches.values_of_lossy("scopes") {
                        Some(scopes) => {
                            config.scopes = scopes;
                        }
                        None => {}
                    }
                    match matches.value_of("redirect") {
                        Some(redirect_url) => {
                            config.redirect_url = redirect_url.to_string();
                        }
                        None => {}
                    };

                    config
                }
            };

            match google_login(&mut config) {
                Ok(_) => (),
                Err(e) => {
                    print_error_and_exit(&e.to_string());
                    unreachable!()
                }
            }

            println!(
                "Successfully logged in and created the configuration profile {}",
                &config.name
            );
        }
        ("accesstoken", Some(matches)) => {
            let config_name = matches.value_of("config").unwrap().to_string();

            let mut config = match ConfigFile::read_config(&config_name) {
                Some(config) => config,
                None => {
                    print_error_and_exit(&format!("No such configuration: {}", &config_name));
                    unreachable!()
                }
            };

            check_token(config.access_token.clone(), &mut config);

            match &config.access_token {
                Some(access_token) => println!("{}", access_token.secret),
                None => {
                    print_error_and_exit(&format!(
                        "Could not read access token from {}. Is the configuration corrupt?",
                        &config.name
                    ));
                    unreachable!()
                }
            };
        }
        ("idtoken", Some(matches)) => {
            let config_name = matches.value_of("config").unwrap().to_string();

            let mut config = match ConfigFile::read_config(&config_name) {
                Some(config) => config,
                None => {
                    print_error_and_exit(&format!("No such configuration: {}", &config_name));
                    unreachable!()
                }
            };

            check_token(config.id_token.clone(), &mut config);

            match &config.id_token {
                Some(id_token) => println!("{}", id_token.secret),
                None => {
                    print_error_and_exit(&format!(
                        "Could not read id token from {}. Is the configuration corrupt?",
                        &config.name
                    ));
                    unreachable!()
                }
            };
        }
        _ => {
            println!("You must select a sub command. See --help");
        }
    }
}

fn print_error_and_exit(error_str: &str) {
    eprintln!("Error: {}", error_str);
    exit(1);
}

fn print_success_and_exit(success_str: &str) {
    println!("{}", success_str);
    exit(0);
}

fn check_token(token: Option<Token>, config: &mut ConfigFile) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token_expiration = match token {
        Some(token) => token.exp,
        None => 0,
    };

    if token_expiration < now {
        match refresh_google_login(config) {
            Ok(_) => {}
            Err(e) => {
                print_error_and_exit(&e.to_string());
                unreachable!()
            }
        }
    }
}

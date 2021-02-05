use std::process::exit;

use clap::{App, Arg, SubCommand};

use googauth_lib::{google_login, ConfigFile, get_access_token_from_config, check_token};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
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
                        if !scopes.is_empty() {
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
                Ok(config_list) => config_list,
                Err(err) => {
                    eprintln!("Error: {:?}", err);
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
                Err(_err) => {
                    // TODO: Check err?
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

                    if let Ok(config) = ConfigFile::config_file(&config_name) {
                        if let Some(config_str) = config.to_str() {
                            println!("Saved configuration to {}", config_str)
                        }
                    }

                    new_config
                }
                Ok(mut config) => {
                    if let Some(client_id) = matches.value_of("clientid") {
                        config.client_id = client_id.to_string();
                    }
                    if let Some(client_secret) = matches.value_of("secret") {
                        config.client_secret = client_secret.to_string();
                    }
                    if let Some(scopes) = matches.values_of_lossy("scopes") {
                        config.scopes = scopes;
                    }
                    if let Some(redirect_url) = matches.value_of("redirect") {
                        config.redirect_url = redirect_url.to_string();
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
            let access_token = match get_access_token_from_config(&config_name) {
                Ok(access_token) => access_token,
                Err(e) => {
                    print_error_and_exit(&e.to_string());
                    unreachable!();
                },
            };
            println!("{}", access_token.secret);
        }
        ("idtoken", Some(matches)) => {
            let config_name = matches.value_of("config").unwrap().to_string();

            let mut config = match ConfigFile::read_config(&config_name) {
                Ok(config) => config,
                Err(err) => {
                    eprintln!("Error when reading configuration: {:?}", err);
                    exit(1);
                }
            };

            if let Err(err) = check_token(config.id_token.clone(), &mut config) {
                eprintln!("Error when checking the token: {:?}", err);
                exit(1);
            }

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

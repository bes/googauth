use std::process::exit;

use clap::{Arg, ArgAction, Command};

use googauth_lib::{
    check_token, get_access_token_from_config, google_login, ConfigBasePath, ConfigFile,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() {
    let config_name_arg = Arg::new("config")
        .value_name("CONFIG NAME")
        .required(true)
        .index(1)
        .help("The configuration name")
        .long_help("The configuration will cache the refresh token and other values to avoid reauthorization on reuse");

    let app = Command::new("googauth")
        .version(VERSION)
        .propagate_version(true)
        .about("Request and store Google OpenID (OAuth) tokens")
        .subcommand(Command::new("list")
            .about("List all the current profiles")
        )
        .subcommand(Command::new("login")
            .arg(config_name_arg.clone())
            .arg(
                Arg::new("clientid")
                    .env("CLIENT_ID")
                    .long("id")
                    .short('i')
                    .help("The client id")
                    .long_help("The client id. Can be created at http://console.developers.google.com"),
            )
            .arg(
                Arg::new("secret")
                    .env("CLIENT_SECRET")
                    .long("secret")
                    .short('s')
                    .help("The client secret")
                    .long_help("The client secret. Can be created at http://console.developers.google.com"),
            )
            .arg(
                Arg::new("scopes")
                    .env("SCOPES")
                    .long("scopes")
                    .short('o')
                    .action(ArgAction::Append)
                    .num_args(1..)
                    .value_delimiter(',')
                    .value_parser(|scopes: &str| {
                        if !scopes.is_empty() {
                            return Ok(scopes.to_string());
                        }
                        Err(String::from("You must specify at least one scope"))
                    })
                    .help("The scopes to request")
                    .long_help("One or more scopes to request from the provider."),
            )
            .arg(
                Arg::new("redirect")
                    .env("REDIRECT")
                    .long("redirect")
                    .short('r')
                    .default_value("http://localhost:8080/")
                    .help("OAuth Redirect URL")
            )
        )
        .subcommand(Command::new("accesstoken")
            .arg(config_name_arg.clone())
        )
        .subcommand(Command::new("idtoken")
            .arg(config_name_arg.clone())
        );

    let config_base_path = match ConfigBasePath::default() {
        Ok(googauth_config_base_path) => googauth_config_base_path,
        Err(err) => {
            println!("No base path found: {:?}", err);
            exit(0);
        }
    };

    let matches = app.get_matches();

    match matches.subcommand() {
        Some(("list", _)) => {
            let config_list = match ConfigFile::list_configs(&config_base_path) {
                Ok(config_list) => config_list,
                Err(err) => {
                    eprintln!("Error: {:?}", err);
                    print_success_and_exit("No configs available");
                    unreachable!()
                }
            };
            for config_file in config_list {
                println!(
                    "{0: <25} | {1: <115}",
                    config_file.name,
                    config_file.scopes.join(", ")
                );
            }
        }
        Some(("login", matches)) => {
            let config_name = match matches.get_one::<String>("config") {
                Some(config_name) => config_name,
                None => {
                    print_error_and_exit("You must specify an configuration name");
                    unreachable!()
                }
            };
            let mut config = match ConfigFile::read_config(&config_name, &config_base_path)
            {
                Err(_err) => {
                    // TODO: Check err?
                    let client_id = match matches.get_one::<String>("clientid") {
                        Some(client_id) => client_id,
                        None => {
                            print_error_and_exit(&format!(
                                "You must specify a client id for the configuration {}",
                                &config_name
                            ));
                            unreachable!()
                        }
                    };
                    let client_secret = match matches.get_one::<String>("secret") {
                        Some(client_secret) => client_secret,
                        None => {
                            print_error_and_exit(&format!(
                                "You must specify a client secret for the configuration {}",
                                &config_name
                            ));
                            unreachable!()
                        }
                    };
                    let scopes = match matches.get_many::<String>("scopes") {
                        Some(scopes) => scopes.cloned().collect::<Vec<_>>(),
                        None => {
                            print_error_and_exit(&format!(
                                "You must specify at least one scope for the configuration {}",
                                &config_name
                            ));
                            unreachable!()
                        }
                    };
                    let redirect_url = match matches.get_one::<String>("redirect") {
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

                    match new_config.save_config(&config_base_path) {
                        Ok(_) => (),
                        Err(e) => {
                            print_error_and_exit(&e.to_string());
                            unreachable!()
                        }
                    }

                    if let Ok(config) =
                        ConfigFile::config_file(&config_name, &config_base_path)
                    {
                        if let Some(config_str) = config.to_str() {
                            println!("Saved configuration to {}", config_str)
                        }
                    }

                    new_config
                }
                Ok(mut config) => {
                    if let Some(client_id) = matches.get_one::<String>("clientid") {
                        config.client_id = client_id.to_string();
                    }
                    if let Some(client_secret) = matches.get_one::<String>("secret") {
                        config.client_secret = client_secret.to_string();
                    }
                    if let Some(scopes) = matches.get_many::<String>("scopes") {
                        config.scopes = scopes.cloned().collect();
                    }
                    if let Some(redirect_url) = matches.get_one::<String>("redirect") {
                        config.redirect_url = redirect_url.to_string();
                    };

                    config
                }
            };

            match google_login(&mut config, &config_base_path).await {
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
        Some(("accesstoken", matches)) => {
            let config_name = matches.get_one::<String>("config").unwrap().clone();
            let access_token =
                match get_access_token_from_config(&config_name, &config_base_path).await {
                    Ok(access_token) => access_token,
                    Err(e) => {
                        print_error_and_exit(&e.to_string());
                        unreachable!();
                    }
                };
            println!("{}", access_token.secret);
        }
        Some(("idtoken", matches)) => {
            let config_name = matches.get_one::<String>("config").unwrap().clone();

            let mut config = match ConfigFile::read_config(&config_name, &config_base_path)
            {
                Ok(config) => config,
                Err(err) => {
                    eprintln!("Error when reading configuration: {:?}", err);
                    exit(1);
                }
            };

            if let Err(err) = check_token(config.id_token.clone(), &mut config, &config_base_path).await {
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

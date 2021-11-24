# googauth

Please see [googauth-lib](https://crates.io/crates/googauth-lib)
if you want to integrate this tool into your own code.

## Features

* Profiles: save each login in a named profile.
* Cache: Each profile saves the last access and id token for ease of use.
* Refresh token: automatically fetches a new (access/id) token if the current one has expired.
* Pipeable: Most commands are designed to be used as the input to other command line programs by the use of pipes.
* User friendly: The goal is to provide decent error messages.

## Help

Using the help section of the program should get you started.

```
./googauth help
```

## Login

Use the login command with a profile name and parameter values for all the required parameters.

```
./googauth login myprofile \
   --scopes "scope1,scope2,scope3" \
   --id "my_client_id" \
   --secret "my_client_secret"
```

At this point your default browser should start and you can login to your Google account.

If the browser doesn't start, you can use the URL that is printed to the terminal.

## Access token

```
./googauth accesstoken myprofile

<ACCESS TOKEN ON STANDARD OUT>
```

## ID Token

```
./googauth idtoken myprofile

<ID TOKEN ON STANDARD OUT>
```

# License

MIT

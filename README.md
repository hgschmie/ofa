# ofa - Manage AWS IAM Roles when using an IdP

Command line access to IdP Authentication and AWS IAM role assignment
without a browser.

## State of IdPs

* Okta - Supported, Functional
* OneLogin - Supported, Functional
* Auth0 - Partially supported, Not functional

### Okta

The Okta code is brittle as it requires to use a semi-documented (https://developer.okta.com/docs/guides/session-cookie/overview/#retrieving-a-session-cookie-via-openid-connect-authorization-endpoint)
way to create the necessary SAML Assertion.

### Onelogin

Only documented APIs are used. Does not support all available authentication methods (patches for WebAuthn wanted!) 

### Auth0

**Auth0 does not work**. It seems to be impossible to create a SAML Assertion from a token (see https://community.auth0.com/t/exchange-a-bearer-token-for-a-saml-assertion/59354). 

## Usage

### For all IdPs

`ofa` manages global settings and profiles to log into an IdP and assume an AWS role.

Each profile contains

* IdP Type and configuration
* Login information and authentication method
* AWS role to assume
* AWS session time

`ofa` uses four sources for each value in order of precedence:

* command line arguments
* profile settings (requires profile selection)
* global settings
* interactive prompt (if running in interactive mode)

profile selection happens through a default profile setting, or a command line flag.


#### commands and flags

The `ofa` application supports the `--help` flag and the `help` command everywhere.

* `ofa defaults set`
* `ofa defaults show`
* `ofa profile create`
* `ofa profile list`
* `ofa profile update`
* `ofa profile remove`
* `ofa password set`
* `ofa password remove`
* `ofa login`

The `ofa version` command displays the version and build information.

##### global flags

Every `ofa` command supports the following global flags:

* `--no-config`

Ignore any config file. Parameters and interactive input must provide all parameters.

* `--interactive`

Force interactive mode (overrides default). `ofa` will prompt for input if required. This is the default unless configured otherwise.

* `--batch`

Never prompt for input. `ofa` will never prompt the user for input.

* `--quiet`

Only output minimal or no information.

* `--verbose`

Output more information during operation. This is the default unless configured otherwise.


#### ofa defaults command

`ofa` manages a set of defaults to use when neither flags or profile settings are available.

By default, `ofa` will prompt for every setting interactively when executing the `set` subcommand.

To set a single flag without prompting:

```
ofa --set-interactive=false --batch
```

`ofa` manages the default state of the `interactive` and `verbose` flags and provides default settings for:

* profile name (which profile to use unless overridden by a command line parameter)
* Username
* IdP type and authentication method
* Base/Organization URL
* IdP specific settings
* AWS role to assume
* AWS session time


### ofa profile command

`ofa` can manage multiple profiles for logging into AWS using an IdP. Profiles are independent and can refer to multiple IdP and AWS accounts.

Each profile may consist of

* Username
* IdP type and authentication method
* Base/Organization URL
* IdP specific settings
* AWS role to assume
* AWS session time

All parameters are optional, the tool may fall back to its defaults or prompt in interactive mode.

The `ofa profile list` command lists all available profiles. Verbose mode shows all profile parameters, quiet mode only the names of the profiles.

To create a new profile, the `ofa profile create` command will either use command line parameters or prompt for the profile settings.

The `ofa profile update` command allows editing of existing profiles.

The `ofa profile delete` command removes an existing profile.


### ofa password command

On supported systems (MacOS has been tested, Linux should work as well), `ofa` can store passwords in the user specific keychain.

IdPs are single signon systems and identified by the Base/Organization URL, so each combination of this URL and a login is unique, even if used in multiple profiles.

`ofa password set` sets a password in the keychain, `ofa password remove` removes it. The `set` command will override an existing password.


Note that the keychain might prompt (with a modal dialog) when using a password. It is not recommended to always allow `ofa` access to a keychain entry as this removes a security factor.


### ofa login command

The `ofa login` command authenticates using the selected IdP and then uses the information to log into AWS, assume a role and create credentials.

This command uses all available sources (command line parameters, profile settings, default settings and interactive input).

A successful login and role selection creates a new set of AWS credentials. These credentials are written into the AWS credentials file using the profile name.

Writing the credentials file can be avoided by using the `--eval` flag. In this case, `ofa` prints output that can be evaluated in the calling shell.


## Using Okta

### Prerequisite: Setting up Okta and AWS

The `ofa` tool assumes that your Okta/AWS setup is using the "AWS Account Federation"
Okta application (see https://www.okta.com/integrations/aws-account-federation/ for details.

This requires a regular Okta account or at least an Okta trial account; developer accounts do not allow installation of applications.

### Okta configuration reference

| Key | Flag | Function |
| --- | ---- | -------- |
| `url` | `--set-url` <br> `--url` | Base/Organization URL.  |
| `okta_app_url` | `--set-okta-app-url` <br> `--okta-app-url` | Application URL. See below. |
| `okta_auth_method` | `--set-okta-auth-method` <br> `--auth-method` | Supported methods are  `push`, `sms` and `token`. | 

* Use the `Okta organization URL`, usually `https://<company name>.okta.com/` as the Base/Organization URL.
* Locate the application URL by logging into the Okta organization, then hover over the AWS application icon in the web view and selecting "Copy Link Address" in the browser. Stripping the query section (`?fromHome=true`) from this URL gives the Okta application URL.

### Okta Example

* Set up defaults and a profile:

```
ofa defaults set --set-user=<user name> --set-okta-auth-method=push --set-url=https://<organization>.okta.com/ --set-session-time=14400 --batch
```

Create defaults for using Okta as IdP. When using a single Okta instance, the username, authentication method and Okta URL will always be the same. Setting them as default makes profile generation simpler.

```
ofa password set
```

As URL and username exist as defaults, this command only prompts for the password and stores it in the keychain.


```
ofa profile create --profile=new_profile --set-profile-type=okta --set-role=<aws role to assume> --set-okta-app-url=<... okta aws app url as described below ...> --batch
```

This command assigns the remaining, profile specific settings to the `new_profile` profile.

```
ofa defaults set --set-profile=new_profile --batch
```

Make the new profile the default unless there is a profile name set with a parameter.


```
ofa login
```

will initiate a login using the default IdP (Okta configured as described below), assume the role in the `new_profile` profile and write AWS credentials in the `[new_profile]` section of the AWS credentials file.

```
eval $(ofa login --eval)
```

allows setting of environment variables without touching the AWS credentials file.


* Set up a second profile:

```
ofa profile create --profile=dev --set-profile-type=okta --set-okta-app-url=<... okta aws app url as described below ...> --batch
```

Unlike the previous profile, this one does not contain an AWS role. If Okta returns more than one role, `ofa` will prompt:

```
ofa login --profile dev
INFO **** Global Flags:
INFO Ignore Configuration:     false (default value)
INFO Verbose:                  true (default value)
INFO Interactive:              true (default value)
INFO **** Login Session:
INFO Profile name:             dev (flag: 'profile')
INFO Okta username:            <okta user name> (global config, key: 'user')
INFO Profile type:             okta (profile [dev], key: 'profile_type')
INFO Base/organization URL:    https://<organization>.okta.com/ (global config, key: 'url')
INFO Okta password:            <configured> (Keychain for Okta URL 'https://<organization>.okta.com/', username '<okta user name>')
INFO Okta AWS app URL:         <... okta app url ...> (profile [dev], key: 'okta_app_url')
INFO Okta auth method:         push (global config, key: 'okta_auth_method')
INFO AWS session time:         14400 (global config, key: 'aws_session_time')
INFO **** Logging into Okta
INFO **** Initiating MFA Challenge
INFO **** Okta login successful
INFO **** Fetching Okta SAML response
INFO **** Selecting AWS role from SAML response
? Select AWS Role:
  ▸ role_1
    role_2
    role_3
```

after selecting a role, `ofa` writes credentials in the AWS credentials file and exits.

---

#### NOTE ABOUT MACOS CODE SIGNING

ofa binaries for MacOS are (for now) not signed. Starting with MacOS 10.15, MacOS will complain (and refuse to open the binary). Go to "Security & Privacy" in preferences, choose the "General" tab and click on "Allow anyway" the first time that this happens. Afterwards, ofa can be used normally. See https://github.com/hashicorp/terraform/issues/23033#issuecomment-542302933 for more details.


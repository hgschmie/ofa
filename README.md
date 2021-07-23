# ofa - Command line AWS credential management with an IdP

Command line access to IdP Authentication and AWS IAM role assignment without a browser.

See the [Changes](CHANGES.md) file for a list of changes and [Development](DEVELOPMENT.md) for information on how to build and contribute to this project.

This software is provided *as is* under MIT license. It may contain bugs and does not work in all possible corner cases. I have access to developer
accounts on OneLogin and Auth0. There is no usable, permanent free tier on Okta, so the Okta support has fallen behind (it should
be functional but not all features may be supported).

## State of IdPs

* Okta - Supported, Functional
* OneLogin - Supported, Functional
* Auth0 - Partially supported, Not functional

### Okta

The Okta code is brittle as it requires to use a semi-documented (https://developer.okta.com/docs/guides/session-cookie/overview/#retrieving-a-session-cookie-via-openid-connect-authorization-endpoint)
way to create the necessary SAML Assertion.

### OneLogin

Only documented APIs are used. Does not support all available authentication methods (patches for WebAuthn wanted!).

Supports the Multi-Account application (will prompt for all roles from all accounts).

There are some minor issues when Push notifications get denied on the mobile app, see https://stackoverflow.com/questions/68478392/onelogin-saml-assertion-verify-factor-with-authentication-denied for details.

### Auth0

**Auth0 does not work**. It seems to be impossible to create a SAML Assertion from a token (see https://community.auth0.com/t/exchange-a-bearer-token-for-a-saml-assertion/59354). 


## Using Okta

### Prerequisite: Setting up Okta and AWS

The `ofa` tool assumes that your Okta/AWS setup is using the "AWS Account Federation"
Okta application (see https://www.okta.com/integrations/aws-account-federation/ for details.

This requires a regular Okta account or at least an Okta trial account; developer accounts do not allow installation of applications.

### Okta configuration reference

| Key | Flag | Function |
| --- | ---- | -------- |
| `url` | `--set-url` <br> `--url` | Base/Organization URL. `https://<subdomain>.okta.com/` |
| `okta_app_url` | `--set-okta-app-url` <br> `--okta-app-url` | Application URL. See below. |
| `okta_auth_method` | `--set-okta-auth-method` <br> `--auth-method` | Supported methods are  `push`, `sms` and `totp`. |

* Use the `Okta organization URL`, usually `https://<company name>.okta.com/` as the Base/Organization URL.
* Locate the application URL by logging into the Okta organization, then hover over the AWS application icon in the web view and selecting "Copy Link Address" in the browser. Stripping the query section (`?fromHome=true`) from this URL gives the Okta application URL.

#### Supported Authentication methods

When using MFA, the user account must be already enrolled using the MFA. `ofa` does not support the enrollment flow.

* `push` - Using the Okta Mobile application. Approve/Deny directly on the mobile application.
* `sms` - Sending a text message, then prompting for the code from the text message.
* `totp` - Using an Authentication application (Google Authenticator, Authy etc.), prompts for the TOTP code.


## Using OneLogin

### Prerequisite: Setting up OneLogin and AWS

The `ofa` tool assumes that your OneLogin/AWS setup is using the "Amazon Web Services", "Amazon Web Services (AWS) Multi Account" or "Amazon Web Services (AWS) Multi Role"
application. There is a great walkthrough at https://onelogin.service-now.com/kb_view.do?sysparm_article=KB0010344 which describes the setup in detail.

Make sure that you can log into your AWS Account or Accounts using the OneLogin Application portal.

This setup works with the OneLogin free / developer tier ("Developer Basic") available at https://www.onelogin.com/developer-signup

Unlike the Okta Trial Accounts, these do not expire (see the /subscription/edit tab in the developer account).


### Prerequisite: Setup API Access

* Using "Developers" -> "API Credentials" -> "New Credential", create a new credential.
* Choose "Authentication only" for permissions.

Copy the "Client ID" and "Client Secret" values.

This credential needs to be shared between all users of the ofa application within an application. It allows users to authenticate with the API so it should be kept confidential. However, it does require a second (login and password) and potentially a third factor (MFA) to actually acccess any service.
It is most useful to track all users that use the `ofa` client tool to authenticate.


### OneLogin configuration reference

| Key | Flag | Function |
| --- | ---- | -------- |
| `url` | `--set-url` <br> `--url` | Base/Organization URL. `https://<subdomain>.onelogin.com/` |
| `onelogin_auth_method` | `--set-onelogin-auth-method` <br> `--onelogin-auth-method` |  Supported methods are `push`, `sms`, `email`, `totp` |
| `onelogin_client_id` | `--set-onelogin-client-id` <br> `--onelogin-client-id` | API Credential client id |
| `onelogin_client_secret` | `--set-onelogin-client-secret` <br> `--onelogin-client-secret` | API Credential client secret |
| `onelogin_app_id` | `--set-onelogin-app-id` <br> `--onelogin-app-id` | OneLogin application id |
| `onelogin_api_url` | `--set-onelogin-api-url` <br> `--onelogin-api-url` | OneLogin API endpoint |

* The tool assumes that it can determine the actual subdomain by taking the first part of the host name of the Base/Organization URL.
* Administrators can locate the application id by opening the application settings page in the Administration portal. The app-id is in the URL: `/apps/<app-id>/edit`.
* OneLogin has multiple API endpoints around the world. If unset, it defaults to `https://api.us.onelogin.com/`.

#### Supported Authentication methods

When using MFA, the user account must be already enrolled using the MFA. `ofa` does not support the enrollment flow.

* `push` - Using the OneLogin Protect application. Approve/Deny directly on the mobile application.
* `sms` - Sending a text message, then prompting for the code from the text message.
* `email` - Sending an email, then prompting for the code from the mail.
* `totp` - Using an Authentication application (Google Authenticator, Authy etc.), prompts for the TOTP code.


#### OneLogin Multi Account setup

OneLogin allows using a single OneLogin application to log into multiple AWS accounts. When using the Application from a brower, AWS will present a selection screen where the accounts and all available roles are listed for user selection.

`ofa` supports this mode, however there are some caveats:

- When the set of roles contains more than one AWS account and the user needs to choose between multiple roles from multiple accounts, the menu selection will contain the AWS account ids in parentheses.
- When the same role name is presented in multiple accounts, role selection will always fall back to the interactive dialog as `ofa` only stores the role name and not the account id in its configuration. This may be fixed in a future version.

If you have full control over the AWS role and account setup, it is recommended to prefix the role names for SAML 2.0 federation roles with some account information (e.g. "dev" or "prod") to make them easier to differentiate.


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


#### ofa profiles and AWS profiles

`ofa` maintains a configuration file that controls the login information for a profile. However, `ofa` was designed to work with arbitrary profile names and
having a profile in ofa itself is not necessary. This is intentional and not a bug.

As `ofa` can be used fully interactive or all settings could be covered by defaults, the following command actually does nothing:

```bash
ofa profile create --profile=new_profile --batch`
```

because there is no setting associated with the profile. It can still be used for logging in:

```bash
ofa login --profile=some_random_name
```

will work well (and use either defaults or interactive inputs) to log into the IdP and then write credentials for "some_random_name" into the AWS credentials file.



### ofa password command

On supported systems (MacOS has been tested, Linux should work as well), `ofa` can store passwords in the user specific keychain.

IdPs are single signon systems and identified by the Base/Organization URL, so each combination of this URL and a login is unique, even if used in multiple profiles.

`ofa password set` sets a password in the keychain, `ofa password remove` removes it. The `set` command will override an existing password.


Note that the keychain might prompt (with a modal dialog) when using a password. It is not recommended to always allow `ofa` access to a keychain entry as this removes a security factor.


### ofa login command

The `ofa login` command authenticates using the selected IdP and then uses the information to log into AWS, assume a role and create credentials.

This command uses all available sources (command line parameters, profile settings, default settings and interactive input).

A successful login and role selection creates a new set of AWS credentials. These credentials are written into the AWS credentials file **using the profile name**.

Writing the credentials file can be avoided by using the `--eval` flag. In this case, `ofa` prints output that can be evaluated in the calling shell.


## Examples

### Okta

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
ofa profile create --profile=new_profile --set-profile-type=okta --set-role=<aws role to assume> --set-okta-app-url=<... okta aws app url as described above ...> --batch
```

This command assigns the remaining, profile specific settings to the `new_profile` profile.

```
ofa defaults set --set-profile=new_profile --batch
```

Make the new profile the default unless there is a profile name set with a parameter.


```
ofa login
```

will initiate a login using the default IdP (Okta configured as described above), assume the role in the `new_profile` profile and write AWS credentials in the `[new_profile]` section of the AWS credentials file.

```
eval $(ofa login --eval)
```

allows setting of environment variables without touching the AWS credentials file.


* Set up a second profile:

```
ofa profile create --profile=dev --set-profile-type=okta --set-okta-app-url=<... okta aws app url as described above ...> --batch
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

### OneLogin

#### 1. Set up defaults

```bash
ofa defaults set --batch \
                 --set-user=<user name> \
                 --set-session-time=14400 \
                 --profile-type=onelogin \
                 --set-url=https://<subdomain>.onelogin.com/ \
                 --set-onelogin-auth-method=push \
                 --set-onelogin-api-url=https://api.<region>.onelogin.com/ \
                 --set-onelogin-app-id=<onelogin app id> \
                 --set-onelogin-client-id=<api access client id> \
                 --set-onelogin-client-secret=<api access client secret>
```

Creates defaults for `ofa`. As this will be using OneLogin, it configures all the OneLogin defaults for a single OneLogin instance where the username, base url and the client parameters will all be the same.

Making them defaults simplifies profile generation. All defaults can be overridden on a per-profile basis.

Notes:

* subdomain name and onelogin app id should be provided by the OneLogin administrator.
* An API access credential (see above) must be set.
* Choose the OneLogin region accordingly (e.g. `us` for US, `eu` for Europe).


#### 2. Set the user password


```bash
ofa password set
```

URL and username exist as defaults, this command only prompts for the password and stores it securely in the keychain.


#### 3. Create a profile

**The name of the profile must match the name of the AWS profile where the credentials are stored!**

```bash
ofa profile create --batch \
                   --profile=new_profile \
                   --set-role=<aws role to assume>
```

This command creates the `new_profile` profile and assigns a specific role to assume.


#### Optional: Make the new profile the default

```
ofa defaults set --set-profile=new_profile --batch
```

Make the new profile the default unless there is a profile name set with a parameter.


#### 4. Retrieve AWS credentials using OneLogin IdP

```
ofa login --profile=new_profile
```

will initiate a login using OneLogin, assume the role in the `new_profile` profile and write AWS credentials in the `[new_profile]` section of the AWS credentials file.

```
eval $(ofa login --profile=new_profile --eval)
```

allows setting of environment variables without writing them to the AWS credentials file.


#### Bonus: Setting multiple profiles


```bash
ofa profile create --batch \
                   --profile=dev \
                   --set-session-time=3600
```

Unlike the previous profile, this one does not contain an AWS role. If OneLogin returns more than one role, `ofa` will prompt for role selection:

```
INFO **** Global Flags:
INFO Ignore Configuration:     false (default value)
INFO Verbose:                  true (flag: 'verbose')
INFO Interactive:              true (default value)
INFO **** Login Session:
INFO Profile name:             dev (flag: 'profile')
INFO Profile type:             onelogin (global config, key: 'idp_type')
INFO Username:                 <username> (global config, key: 'user')
INFO Base/organization URL:    https://<subdomain>.onelogin.com/ (global config, key: 'url')
INFO Password:                 <configured> (Keychain for Okta URL 'https://<subdomain>.onelogin.com/', username '<username>')
INFO Onelogin auth method:     push (global config, key: 'onelogin_auth_method')
INFO Onelogin Application Client Id: <api authencation client id> (global config, key: 'onelogin_client_id')
INFO Onelogin Application Client Secret: <configured> (global config, key: 'onelogin_client_secret')
INFO Onelogin Application Id:  <app id> (global config, key: 'onelogin_app_id')
INFO Onelogin API Url:         https://api.us.onelogin.com/ (global config, key: 'onelogin_api_url')
INFO AWS session duration:     3600 (profile [dev], key: 'aws_session_time')
INFO **** Logging into Onelogin
INFO **** Initiating MFA Challenge
INFO **** Selecting AWS role from SAML response
? Select AWS Role:
  ▸ role_A (aws_account_id 1)
    role_B (aws_account_id 1)
    role_1 (aws_account_id 2)
    role_2 (aws_account_id 2)
    role_A (aws_account_id 3)
    role_B (aws_account_id 3)
```

In this example, there are multiple AWS accounts configured (aws_account_id 1-3) and for some of them, the role names are overlapping (role_A and role_B are present in aws_account_id 1 and aws_account_id 2).


package ofa

const (
    // global command line flags

    FlagInteractive = "interactive"
    FlagBatch       = "batch"
    FlagVerbose     = "verbose"
    FlagQuiet       = "quiet"
    FlagNoConfig    = "no-config"

    FlagSetInteractive = "set-interactive"
    FlagSetVerbose     = "set-verbose"

    // set value flags

    FlagSetOktaAuthMethod = "set-okta-auth-method"
    FlagSetOktaAppURL     = "set-okta-app-url"
    FlagSetOktaURL        = "set-okta-url"

    FlagSetAuth0URL          = "set-auth0-url"
    FlagSetAuth0AuthMethod   = "set-auth0-auth-method"
    FlagSetAuth0ClientId     = "set-auth0-client-id"
    FlagSetAuth0ClientSecret = "set-auth0-client-secret"

    FlagSetProfile     = "set-profile"
    FlagSetProfileType = "set-profile-type"
    FlagSetRole        = "set-role"
    FlagSetSessionTime = "set-session-time"
    FlagSetUser        = "set-user"

    // value flags

    FlagOktaAuthMethod = "okta-auth-method"
    FlagOktaAppURL     = "okta-app-url"
    FlagOktaURL        = "okta-url"

    FlagAuth0AuthMethod   = "auth0-auth-method"
    FlagAuth0URL          = "auth0-url"
    FlagAuth0ClientId     = "auth0-client-id"
    FlagAuth0ClientSecret = "auth0-client-secret"

    FlagPassword    = "password"
    FlagProfile     = "profile"
    FlagRole        = "role"
    FlagSessionTime = "session-time"
    FlagUser        = "user"
    FlagProfileType = "profile-type"

    FlagDescSetVerbose     = "Sets the default verbose flag."
    FlagDescSetInteractive = "Sets the default interactive flag."
    FlagDescSetProfileName = "Sets the default profile name."

    FlagDescSetProfileType = "Sets the profile type (okta, auth0)."
    FlagDescSetUser        = "Sets the username."

    FlagDescSetOktaAuthMethod = "Sets the Okta Auth method."
    FlagDescSetOktaAppURL     = "Sets the Okta AWS app URL."
    FlagDescSetOktaURL        = "Sets the Okta organization URL."

    FlagDescSetAuth0AuthMethod   = "Sets the Auth0 Auth method."
    FlagDescSetAuth0URL          = "Sets the Auth0 Tenant URL."
    FlagDescSetAuth0ClientId     = "Sets the Auth0 Client Id."
    FlagDescSetAuth0ClientSecret = "Sets the Auth0 Client Secret."

    FlagDescSetRole        = "Sets the AWS role to assume."
    FlagDescSetSessionTime = "Sets the AWS session time."

    FlagDescOktaAuthMethod = "Okta Auth method to use."
    FlagDescOktaAppURL     = "Okta AWS app URL to use."
    FlagDescOktaURL        = "Okta organization URL to use."

    FlagDescUser        = "Username to use."
    FlagDescProfileType = "Profile Type to use (okta, auth0)."
    FlagDescPassword    = "Password to use."
    FlagDescRole        = "AWS role to assume."
    FlagDescSessionTime = "AWS session time to use."

    profilePrefix = "profile_"

    // global config keys

    globalKeyVerbose     = "verbose"
    globalKeyInteractive = "interactive"
    globalKeyProfile     = "profile"

    // profile config keys

    profileKeyProfileType = "profile_type"
    profileKeyUser        = "user"

    profileKeyOktaAuthMethod = "okta_auth_method"
    profileKeyOktaAppURL     = "okta_app_url"
    profileKeyOktaURL        = "okta_url"

    profileKeyAuth0AuthMethod   = "auth0_auth_method"
    profileKeyAuth0URL          = "auth0_url"
    profileKeyAuth0ClientId     = "auth0_client_id"
    profileKeyAuth0ClientSecret = "auth0_client_secret"

    profileKeyRole        = "aws_role"
    profileKeySessionTime = "aws_session_time"

    // global labels

    labelIgnoreConfig = "Ignore Configuration"
    labelProfile      = "Profile name"
    labelProfileType  = "Profile type"
    labelInteractive  = "Interactive"
    labelVerbose      = "Verbose"

    // profile labels

    labelOktaAuthMethod = "Okta auth method"
    labelOktaAppURL     = "Okta AWS app URL"
    labelOktaURL        = "Okta organization URL"

    labelAuth0AuthMethod   = "Auth0 auth method"
    labelAuth0URL          = "Auth0 Tenant URL"
    labelAuth0ClientId     = "Auth0 Application Client Id"
    labelAuth0ClientSecret = "Auth0 Application Client Secret"

    labelPassword    = "Password"
    labelRole        = "AWS role"
    labelSessionTime = "AWS session duration"
    labelUser        = "Username"
)

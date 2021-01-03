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

    FlagSetAuthMethod  = "set-auth-method"
    FlagSetOktaAppURL  = "set-okta-app-url"
    FlagSetOktaURL     = "set-okta-url"
    FlagSetProfile     = "set-profile"
    FlagSetRole        = "set-role"
    FlagSetSessionTime = "set-session-time"
    FlagSetUser        = "set-user"

    // value flags

    FlagAuthMethod  = "auth-method"
    FlagOktaAppURL  = "okta-app-url"
    FlagOktaURL     = "okta-url"
    FlagPassword    = "password"
    FlagProfile     = "profile"
    FlagRole        = "role"
    FlagSessionTime = "session-time"
    FlagUser        = "user"

    FlagDescSetVerbose     = "Sets the default verbose flag."
    FlagDescSetInteractive = "Sets the default interactive flag."
    FlagDescSetProfileName = "Sets the default profile name."

    FlagDescSetAuthMethod  = "Sets the Okta Auth method."
    FlagDescSetOktaAppURL  = "Sets the Okta AWS app URL."
    FlagDescSetOktaURL     = "Sets the Okta organization URL."
    FlagDescSetRole        = "Sets the AWS role to assume."
    FlagDescSetSessionTime = "Sets the AWS session time."
    FlagDescSetUser        = "Sets the Okta user."

    FlagDescAuthMethod  = "Okta Auth method to use."
    FlagDescOktaAppURL  = "Okta AWS app URL to use."
    FlagDescOktaURL     = "Okta organization URL to use."
    FlagDescPassword    = "Okta passwort to use."
    FlagDescRole        = "AWS role to assume."
    FlagDescSessionTime = "AWS session time to use."
    FlagDescUser        = "Okta user to use."

    // user prompts

    promptAuthMethod  = "Okta auth method"
    promptOktaAppURL  = "Okta AWS app URL"
    promptOktaURL     = "Okta organization URL"
    promptPassword    = "Okta password"
    promptProfile     = "Profile name"
    promptRole        = "AWS role"
    promptSessionTime = "AWS Session duration"
    promptUser        = "Okta username"

    profilePrefix = "profile_"

    // global config keys

    globalKeyVerbose     = "verbose"
    globalKeyInteractive = "interactive"
    globalKeyProfile     = "profile"

    // profile config keys

    profileKeyAuthMethod  = "okta_auth_method"
    profileKeyOktaAppURL  = "okta_app_url"
    profileKeyOktaURL     = "okta_url"
    profileKeyRole        = "aws_role"
    profileKeySessionTime = "aws_session_time"
    profileKeyUser        = "okta_user"

    // global labels

    labelIgnoreConfig = "Ignore Configuration"
    labelProfile      = "Profile name"
    labelInteractive  = "Interactive"
    labelVerbose      = "Verbose"

    // profile labels

    labelAuthMethod  = "Okta auth method"
    labelOktaAppURL  = "Okta AWS app URL"
    labelOktaURL     = "Okta organisation URL"
    labelPassword    = "Okta password"
    labelRole        = "AWS role"
    labelSessionTime = "AWS session time"
    labelUser        = "Okta username"
)

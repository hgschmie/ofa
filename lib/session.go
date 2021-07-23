package ofa

import (
    "fmt"
    "net/url"
    "strings"

    "github.com/go-playground/validator/v10"
    "github.com/spf13/pflag"
)

const (
    defaultSessionDurationInSec = 3600
)

var (
    validate = validator.New()
)

//
// LoginSession is the main Session structure for the ofa application.
//
type LoginSession struct {
    ProfileName    string   `validate:"omitempty"`
    URL            *url.URL `validate:"required,url"`
    User           string   `validate:"required"`
    Password       *string  `validate:"required"`
    ProfileType    string   `validate:"required,oneof=okta auth0 onelogin"`
    AwsRole        *string  `validate:"omitempty"`
    AwsSessionTime *int64   `validate:"omitempty,gte=3600,lte=86400"` // one hour to one day

    IdentityProvider identityProvider
    rootConfig       ConfigProvider
    flagConfig       ConfigProvider
    profileConfig    ConfigProvider
}

type identityProvider interface {
    Configure(config *LoginSession) error
    Validate() error
    Login() (*string, error)
    name() string
    providerProfile() IdpProfile

    // Flags for permanently settings IdP settings
    ConfigurationFlags(flags *pflag.FlagSet)
    // Flags for overriding IdP settings
    OverrideFlags(flags *pflag.FlagSet)
}

//
// CreateLoginSession creates a new configuration object with all the fields filled in
//
func CreateLoginSession(flags *pflag.FlagSet) (*LoginSession, error) {

    session := &LoginSession{ProfileName: ""}

    session.rootConfig = defaultConfigProvider()
    session.flagConfig = newFlagConfig(flags, false)

    // initialize the profile code. default profile name is stored in the root, next to all profile definitions
    profileName := evaluateString(labelProfile,
        session.flagConfig(FlagProfile),      // --profile flag
        session.rootConfig(globalKeyProfile), // root level configuration key "profile"
        profileMenu(true)) // interactive prompt

    session.profileConfig = newNullConfig()

    // if a profile is present, there can be a store configuration or a keychain password
    if profileName != nil {
        session.ProfileName = *profileName
        session.profileConfig = newProfileConfigProvider(session.ProfileName)
    }

    session.ProfileType = *evaluateString(labelProfileType,
        session.flagConfig(FlagProfileType),          // --profile-type flag
        session.profileConfig(profileKeyProfileType), // profile level configuration key "profile_type"
        session.rootConfig(profileKeyProfileType),    // global configuration key "profile_type"
        interactiveMenu(labelProfileType, availableIdp, nil))

    session.User = *evaluateString(labelUser,
        session.flagConfig(FlagUser),                // --user flag
        session.profileConfig(profileKeyUser),       // profile level configuration key "user"
        session.rootConfig(profileKeyUser),          // global configuration key "user"
        interactiveStringValue(labelUser, nil, nil), // interactive prompt
        constantStringValue(""))

    var err error

    session.URL, err = getURL(evaluateString(labelURL,
        session.flagConfig(FlagURL),
        session.profileConfig(profileKeyURL),
        session.rootConfig(profileKeyURL),
        interactiveStringValue(labelURL, nil, validateURL)))

    if err != nil {
        return nil, err
    }

    keychainConfigProvider := newKeychainEntry(session.URL)

    session.Password = evaluateMask(labelPassword,
        session.flagConfig(FlagPassword),     // --password flag
        keychainConfigProvider(session.User), // keychain stored password
        interactivePasswordValue(labelPassword)) // interactive prompt

    var ok bool

    if session.IdentityProvider, ok = IdentityProviders[strings.ToLower(session.ProfileType)]; !ok {
        return nil, fmt.Errorf("Unknown profile type '%s' for '%s'", session.ProfileType, session.ProfileName)
    }

    err = session.IdentityProvider.Configure(session)
    if err != nil {
        return nil, err
    }

    session.AwsRole = evaluateString(labelRole,
        session.flagConfig(FlagRole),
        session.profileConfig(profileKeyRole),
        session.rootConfig(profileKeyRole))

    session.AwsSessionTime = evaluateInt(labelSessionTime,
        session.flagConfig(FlagSessionTime),
        session.profileConfig(profileKeySessionTime),
        session.rootConfig(profileKeySessionTime),
        interactiveIntValue(labelSessionTime, toIP(defaultSessionDurationInSec)))

    if err := validate.Struct(session); err != nil {
        return nil, err
    }

    return session, nil
}

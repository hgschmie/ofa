package ofa

import (
    "fmt"
    "strings"

    "github.com/go-playground/validator/v10"
    "github.com/spf13/pflag"
)

const (
    defaultSessionDurationInSec = 3600
)

var (
    validate = validator.New()

    providers = map[string]LoginProvider{
        "okta":  &OktaSession{},
        "auth0": &Auth0Session{},
    }
)

//
// LoginSession is the Session structure for the ofa application.
//
type LoginSession struct {
    ProfileName    string  `validate:"omitempty"`
    User           string  `validate:"required"`
    Password       *string `validate:"required"`
    ProfileType    string  `validate:"required,oneof=okta auth0"` // must match the providers structure above!
    AwsRole        *string `validate:"omitempty"`
    AwsSessionTime *int64  `validate:"omitempty,gte=3600,lte=86400"` // one hour to one day

    Provider      LoginProvider
    RootConfig    ConfigProvider
    FlagConfig    ConfigProvider
    ProfileConfig ConfigProvider
}

type LoginProvider interface {
    Configure(config *LoginSession) error
    Validate() (error)
    Login() (*string, error)
    InitiateSamlSession(sessionToken string) (*string, error)
}

//
// CreateLoginSession creates a new configuration object with all the fields filled in
//
func CreateLoginSession(flags *pflag.FlagSet) (*LoginSession, error) {

    session := &LoginSession{ProfileName: ""}

    session.RootConfig = defaultConfigProvider()
    session.FlagConfig = newFlagConfig(flags, false)

    // initialize the profile code. default profile name is stored in the root, next to all profile definitions
    profileName := evaluateString(labelProfile,
        session.FlagConfig(FlagProfile),      // --profile flag
        session.RootConfig(globalKeyProfile), // root level configuration key "profile"
        profileMenu(true)) // interactive prompt

    session.ProfileConfig = newNullConfig()

    // if a profile is present, there can be a store configuration or a keychain password
    if profileName != nil {
        session.ProfileName = *profileName
        session.ProfileConfig = newProfileConfigProvider(session.ProfileName)
    }

    session.ProfileType = *evaluateString(labelProfileType,
        session.FlagConfig(FlagProfileType),          // --profile-type flag
        session.ProfileConfig(profileKeyProfileType), // profile level configuration key "profile_type"
        session.RootConfig(profileKeyProfileType),    // global configuration key "profile_type"
        interactiveMenu(labelProfileType, profileTypes, nil))

    session.User = *evaluateString(labelUser,
        session.FlagConfig(FlagUser),                // --user flag
        session.ProfileConfig(profileKeyUser),       // profile level configuration key "user"
        session.RootConfig(profileKeyUser),          // global configuration key "user"
        interactiveStringValue(labelUser, nil, nil), // interactive prompt
        constantStringValue(""))

    var err error
    var ok bool

    if session.Provider, ok = providers[strings.ToLower(session.ProfileType)]; !ok {
        return nil, fmt.Errorf("Unknown profile type '%s' for '%s'", session.ProfileType, session.ProfileName)
    }

    err = session.Provider.Configure(session)
    if err != nil {
        return nil, err
    }

    session.AwsRole = evaluateString(labelRole,
        session.FlagConfig(FlagRole),
        session.ProfileConfig(profileKeyRole),
        session.RootConfig(profileKeyRole))

    session.AwsSessionTime = evaluateInt(labelSessionTime,
        session.FlagConfig(FlagSessionTime),
        session.ProfileConfig(profileKeySessionTime),
        session.RootConfig(profileKeySessionTime),
        interactiveIntValue(labelSessionTime, toIP(defaultSessionDurationInSec)))

    if err := validate.Struct(session); err != nil {
        return nil, err
    }

    return session, nil
}

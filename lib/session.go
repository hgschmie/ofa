package ofa

import (
    "net/url"

    "github.com/go-playground/validator/v10"
    "github.com/spf13/pflag"
)

const (
    defaultSessionDurationInSec = 3600
)

var (
    validate = validator.New()

    authMethods = map[string]*string{
        "Push Notification":                 toSP("push"),
        "Text Message":                      toSP("sms"),
        "TOTP Token (Google Authenticator)": toSP("token"),
        "<unset>":                           nil,
    }
)

//
// LoginSession is the Session structure for the ofa application.
//
type LoginSession struct {
    ProfileName string  `validate:"omitempty"`
    User        string  `validate:"required"`
    Password    *string `validate:"required"`

    OktaURL        *url.URL `validate:"required,url"`
    OktaAppURL     *url.URL `validate:"required,url"`
    OktaAuthMethod *string  `validate:"omitempty,oneof=token sms push"`

    AwsRole        *string `validate:"omitempty"`
    AwsSessionTime *int64  `validate:"omitempty,gte=3600,lte=86400"` // one hour to one day
}

//
// CreateLoginSession creates a new configuration object with all the fields filled in
//
func CreateLoginSession(flags *pflag.FlagSet) (*LoginSession, error) {

    rootConfigProvider := defaultConfigProvider()
    flagConfigProvider := newFlagConfigProvider(flags, false)

    session := &LoginSession{ProfileName: ""}

    // initialize the profile code. default profile name is stored in the root, next to all profile definitions
    profileName := evaluateString(labelProfile,
        flagConfigProvider(FlagProfile),      // --profile flag
        rootConfigProvider(globalKeyProfile), // root level configuration key "profile"
        profileMenu(true)) // interactive prompt

    profileConfigProvider := newNullConfigProvider()

    // if a profile is present, there can be a store configuration or a keychain password
    if profileName != nil {
        session.ProfileName = *profileName
        profileConfigProvider = newProfileConfigProvider(session.ProfileName)
    }

    session.User = *evaluateString(labelUser,
        flagConfigProvider(FlagUser),                // --user flag
        profileConfigProvider(profileKeyUser),       // profile level configuration key "okta_user"
        rootConfigProvider(profileKeyUser),          // global configuration key "okta_user"
        interactiveStringValue(labelUser, nil, nil), // interactive prompt
        defaultStringValue(""))

    var err error

    session.OktaURL, err = getURL(evaluateString(labelOktaURL,
        flagConfigProvider(FlagOktaURL),
        profileConfigProvider(profileKeyOktaURL),
        rootConfigProvider(profileKeyOktaURL),
        interactiveStringValue(labelOktaURL, nil, validateURL)))

    if err != nil {
        return nil, err
    }

    keychainConfigProvider := newKeychainEntry(session.OktaURL)

    session.Password = evaluateMask(labelPassword,
        flagConfigProvider(FlagPassword),     // --password flag
        keychainConfigProvider(session.User), // keychain stored password
        interactivePasswordValue(labelPassword)) // interactive prompt

    session.OktaAppURL, err = getURL(evaluateString(labelOktaAppURL,
        flagConfigProvider(FlagOktaAppURL),
        profileConfigProvider(profileKeyOktaAppURL),
        rootConfigProvider(profileKeyOktaAppURL),
        interactiveStringValue(labelOktaAppURL, nil, validateURL)))

    if err != nil {
        return nil, err
    }

    session.OktaAuthMethod = evaluateString(labelAuthMethod,
        flagConfigProvider(FlagAuthMethod),
        profileConfigProvider(profileKeyAuthMethod),
        rootConfigProvider(profileKeyAuthMethod),
        interactiveMenu(labelAuthMethod, authMethods, nil))

    session.AwsRole = evaluateString(labelRole,
        flagConfigProvider(FlagRole),
        profileConfigProvider(profileKeyRole),
        rootConfigProvider(profileKeyRole))

    session.AwsSessionTime = evaluateInt(labelSessionTime,
        flagConfigProvider(FlagSessionTime),
        profileConfigProvider(profileKeySessionTime),
        rootConfigProvider(profileKeySessionTime),
        interactiveIntValue(labelSessionTime, toIP(defaultSessionDurationInSec)))

    if err := validate.Struct(session); err != nil {
        return nil, err
    }

    return session, nil
}

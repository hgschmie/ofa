package ofa

import (
    "net/url"

    "github.com/go-playground/validator/v10"
    log "github.com/sirupsen/logrus"
    "github.com/spf13/pflag"
)

const (
    defaultSessionDurationInSec = 3600
)

var (
    validate = validator.New()

    oktaAuthMethods = map[string]*string{
        "Push Notification":                  toSP("push"),
        "Text Message":                       toSP("sms"),
        "TOTP (Google Authenticator, Authy)": toSP("token"),
        "<unset>":                            nil,
    }

    auth0AuthMethods = map[string]*string{
        "Push Notification":                  toSP("push"),
        "Text Message":                       toSP("sms"),
        "Voice Message":                      toSP("voice"),
        "TOTP (Google Authenticator, Authy)": toSP("token"),
        "Recovery Token":                     toSP("recovery-token"),
        "<unset>":                            nil,
    }
)

//
// LoginSession is the Session structure for the ofa application.
//
type LoginSession struct {
    ProfileName    string  `validate:"omitempty"`
    User           string  `validate:"required"`
    Password       *string `validate:"required"`
    ProfileType    string  `validate:"required,oneof=okta auth0"`
    Okta           *OktaSession
    Auth0          *Auth0Session
    AwsRole        *string `validate:"omitempty"`
    AwsSessionTime *int64  `validate:"omitempty,gte=3600,lte=86400"` // one hour to one day
}

type OktaSession struct {
    URL        *url.URL `validate:"required,url"`
    AppURL     *url.URL `validate:"required,url"`
    AuthMethod *string  `validate:"omitempty,oneof=token sms push"`
}

type Auth0Session struct {
    URL          *url.URL `validate:"required,url"`
    AuthMethod   *string  `validate:"omitempty,oneof=push sms voice totp recovery-code"`
    ClientId     *string  `validate:"required"`
    ClientSecret *string  `validate:"required"`
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

    session.ProfileType = *evaluateString(labelProfileType,
        flagConfigProvider(FlagProfileType),          // --profile-type flag
        profileConfigProvider(profileKeyProfileType), // profile level configuration key "profile_type"
        rootConfigProvider(profileKeyProfileType),    // global configuration key "profile_type"
        interactiveMenu(labelProfileType, profileTypes, nil))

    session.User = *evaluateString(labelUser,
        flagConfigProvider(FlagUser),                // --user flag
        profileConfigProvider(profileKeyUser),       // profile level configuration key "user"
        rootConfigProvider(profileKeyUser),          // global configuration key "user"
        interactiveStringValue(labelUser, nil, nil), // interactive prompt
        defaultStringValue(""))

    var err error

    switch session.ProfileType {
    case "okta":
        session.Okta = &OktaSession{}

        session.Okta.URL, err = getURL(evaluateString(labelOktaURL,
            flagConfigProvider(FlagOktaURL),
            profileConfigProvider(profileKeyOktaURL),
            rootConfigProvider(profileKeyOktaURL),
            interactiveStringValue(labelOktaURL, nil, validateURL)))

        if err != nil {
            return nil, err
        }

        keychainConfigProvider := newKeychainEntry(session.Okta.URL)

        session.Password = evaluateMask(labelPassword,
            flagConfigProvider(FlagPassword),     // --password flag
            keychainConfigProvider(session.User), // keychain stored password
            interactivePasswordValue(labelPassword)) // interactive prompt

        session.Okta.AppURL, err = getURL(evaluateString(labelOktaAppURL,
            flagConfigProvider(FlagOktaAppURL),
            profileConfigProvider(profileKeyOktaAppURL),
            rootConfigProvider(profileKeyOktaAppURL),
            interactiveStringValue(labelOktaAppURL, nil, validateURL)))

        if err != nil {
            return nil, err
        }

        session.Okta.AuthMethod = evaluateString(labelOktaAuthMethod,
            flagConfigProvider(FlagOktaAuthMethod),
            profileConfigProvider(profileKeyOktaAuthMethod),
            rootConfigProvider(profileKeyOktaAuthMethod),
            interactiveMenu(labelOktaAuthMethod, oktaAuthMethods, nil))

        if err := validate.Struct(session.Okta); err != nil {
            return nil, err
        }

    case "auth0":
        session.Auth0 = &Auth0Session{}

        session.Auth0.URL, err = getURL(evaluateString(labelAuth0URL,
            flagConfigProvider(FlagAuth0URL),
            profileConfigProvider(profileKeyAuth0URL),
            rootConfigProvider(profileKeyAuth0URL),
            interactiveStringValue(labelAuth0URL, nil, validateURL)))

        if err != nil {
            return nil, err
        }

        keychainConfigProvider := newKeychainEntry(session.Auth0.URL)

        session.Password = evaluateMask(labelPassword,
            flagConfigProvider(FlagPassword),     // --password flag
            keychainConfigProvider(session.User), // keychain stored password
            interactivePasswordValue(labelPassword)) // interactive prompt

        session.Auth0.AuthMethod = evaluateString(labelAuth0AuthMethod,
            flagConfigProvider(FlagAuth0AuthMethod),
            profileConfigProvider(profileKeyAuth0AuthMethod),
            rootConfigProvider(profileKeyAuth0AuthMethod),
            interactiveMenu(labelAuth0AuthMethod, auth0AuthMethods, nil))

        session.Auth0.ClientId = evaluateString(labelAuth0ClientId,
            flagConfigProvider(FlagAuth0ClientId),
            profileConfigProvider(profileKeyAuth0ClientId),
            rootConfigProvider(profileKeyAuth0ClientId),
            interactiveStringValue(labelAuth0ClientId, nil, nil))

        session.Auth0.ClientSecret = evaluateMask(labelAuth0ClientSecret,
            flagConfigProvider(FlagAuth0ClientSecret),
            profileConfigProvider(profileKeyAuth0ClientSecret),
            rootConfigProvider(profileKeyAuth0ClientSecret),
            interactivePasswordValue(labelAuth0ClientSecret))

        if err := validate.Struct(session.Auth0); err != nil {
            return nil, err
        }
    default:
        log.Panicf("Unknown profile type: %s", session.ProfileType)
    }

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

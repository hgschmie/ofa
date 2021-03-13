package ofa

import (
    "fmt"
    "strings"

    log "github.com/sirupsen/logrus"
    "github.com/spf13/pflag"
    "github.com/spf13/viper"
)

type ProfileSettings struct {
    ProfileName    *string
    ProfileType    *string `validate:"omitempty,oneof okta auth0"`
    User           *string
    Okta           *OktaProfileSettings
    Auth0          *Auth0ProfileSettings
    AwsRole        *string
    AwsSessionTime *int64 `validate:"omitempty,gte=3600,lte=86400"`
}

var (
    profileTypeOkta  = toSP("okta")
    profileTypeAuth0 = toSP("auth0")

    profileTypes = map[string]*string{
        "Okta":  profileTypeOkta,
        "Auth0": profileTypeAuth0,
    }
)

type OktaProfileSettings struct {
    URL        *string `validate:"omitempty,url"`
    AppURL     *string `validate:"omitempty,url"`
    AuthMethod *string `validate:"omitempty,oneof=token sms push"`
}

type Auth0ProfileSettings struct {
    URL          *string `validate:"omitempty,url"`
    AuthMethod   *string `validate:"omitempty,oneof=push sms voice totp recovery-code"`
    ClientId     *string `validate:"omitempty,url"`
    ClientSecret *string `validate:"omitempty,url"`
}

func (p *ProfileSettings) Display(profileName *string) {
    if profileName != nil {
        // actual profile
        Information("")
        Information("**** Profile [%s - %s] settings:", *profileName, *p.ProfileType)
    } else {
        // global settings
        logStringSetting(profilePrompt(profileName, labelProfile), p.ProfileName)
    }
    logStringSetting(profilePrompt(profileName, labelUser), p.User)

    if p.Okta != nil {
        logStringSetting(profilePrompt(profileName, labelOktaAuthMethod), p.Okta.AuthMethod)
        logStringSetting(profilePrompt(profileName, labelOktaURL), p.Okta.URL)
        logStringSetting(profilePrompt(profileName, labelOktaAppURL), p.Okta.AppURL)
    }

    if p.Auth0 != nil {
        logStringSetting(profilePrompt(profileName, labelAuth0AuthMethod), p.Auth0.AuthMethod)
        logStringSetting(profilePrompt(profileName, labelAuth0URL), p.Auth0.URL)
        logStringSetting(profilePrompt(profileName, labelAuth0ClientId), p.Auth0.ClientId)
    }

    logStringSetting(profilePrompt(profileName, labelRole), p.AwsRole)
    logIntSetting(profilePrompt(profileName, labelSessionTime), p.AwsSessionTime)
}

func ListProfiles() (*DefaultSettings, map[string]*ProfileSettings) {
    d := &DefaultSettings{}
    p := map[string]*ProfileSettings{}

    if !*globalNoConfig {

        d.Verbose = getBool(store, globalKeyVerbose)
        d.Interactive = getBool(store, globalKeyInteractive)
        // load the profile defaults
        d.Profile = *loadProfile(store, getString(store, globalKeyProfile))

        for k := range store.AllSettings() {
            if profile, ok := stripProfileKey(k); ok {
                substore := store.Sub(k)
                p[*profile] = loadProfile(substore, profile)
            }
        }
    }

    return d, p
}

func CreateProfileSettings(flags *pflag.FlagSet, rootProfileName *string, defaultSettings ProfileSettings) (*ProfileSettings, error) {
    profileSettings := &ProfileSettings{ProfileName: defaultSettings.ProfileName}

    flagConfigProvider := newFlagConfigProvider(flags, false)

    profileSettings.ProfileType = evaluateString(labelProfileType,
        flagConfigProvider(FlagSetProfileType),
        interactiveMenu(profilePrompt(rootProfileName, labelProfileType), profileTypes, defaultSettings.ProfileType))

    if rootProfileName != nil && profileSettings.ProfileType == nil {
        log.Fatalf("A profile type must be selected!")
    }

    // root profile may contain both okta and auth0, everything else can have only one.

    if rootProfileName == nil || profileSettings.ProfileType == profileTypeOkta {
        profileSettings.Okta = &OktaProfileSettings{}
    }
    if rootProfileName == nil || profileSettings.ProfileType == profileTypeAuth0 {
        profileSettings.Auth0 = &Auth0ProfileSettings{}
    }

    profileSettings.User = evaluateString(labelUser,
        flagConfigProvider(FlagSetUser),
        interactiveStringValue(profilePrompt(rootProfileName, labelUser), defaultSettings.User, nil))

    // Okta

    if profileSettings.Okta != nil {
        profileSettings.Okta.URL = evaluateString(labelOktaURL,
            flagConfigProvider(FlagSetOktaURL),
            interactiveStringValue(profilePrompt(rootProfileName, labelOktaURL), defaultSettings.Okta.URL, validateURL))

        profileSettings.Okta.AppURL = evaluateString(labelOktaAppURL,
            flagConfigProvider(FlagSetOktaAppURL),
            interactiveStringValue(profilePrompt(rootProfileName, labelOktaAppURL), defaultSettings.Okta.AppURL, validateURL))

        profileSettings.Okta.AuthMethod = evaluateString(labelOktaAuthMethod,
            flagConfigProvider(FlagSetOktaAuthMethod),
            interactiveMenu(profilePrompt(rootProfileName, labelOktaAuthMethod), oktaAuthMethods, defaultSettings.Okta.AuthMethod))
    }

    // auth0

    if profileSettings.Auth0 != nil {
        profileSettings.Auth0.URL = evaluateString(labelAuth0URL,
            flagConfigProvider(FlagSetAuth0URL),
            interactiveStringValue(profilePrompt(rootProfileName, labelAuth0URL), defaultSettings.Auth0.URL, validateURL))

        profileSettings.Auth0.AuthMethod = evaluateString(labelAuth0AuthMethod,
            flagConfigProvider(FlagSetAuth0AuthMethod),
            interactiveMenu(profilePrompt(rootProfileName, labelAuth0AuthMethod), auth0AuthMethods, defaultSettings.Auth0.AuthMethod))

        profileSettings.Auth0.ClientId = evaluateString(labelAuth0ClientId,
            flagConfigProvider(FlagSetAuth0ClientId),
            interactiveStringValue(profilePrompt(rootProfileName, labelAuth0ClientId), defaultSettings.Auth0.ClientId, nil))

        profileSettings.Auth0.ClientSecret = evaluateString(labelAuth0ClientSecret,
            flagConfigProvider(FlagSetAuth0ClientSecret),
            interactiveStringValue(profilePrompt(rootProfileName, labelAuth0ClientSecret), defaultSettings.Auth0.ClientSecret, nil))
    }

    // AWS

    profileSettings.AwsRole = evaluateString(labelRole,
        flagConfigProvider(FlagSetRole),
        interactiveStringValue(profilePrompt(rootProfileName, labelRole), defaultSettings.AwsRole, nil))

    profileSettings.AwsSessionTime = evaluateInt(labelSessionTime,
        flagConfigProvider(FlagSetSessionTime),
        interactiveIntValue(profilePrompt(rootProfileName, labelSessionTime), defaultSettings.AwsSessionTime))

    if err := validate.Struct(profileSettings); err != nil {
        return nil, err
    }

    if profileSettings.Okta != nil {
        if err := validate.Struct(profileSettings.Okta); err != nil {
            return nil, err
        }
    }

    if profileSettings.Auth0 != nil {
        if err := validate.Struct(profileSettings.Auth0); err != nil {
            return nil, err
        }
    }

    return profileSettings, nil
}

func StoreProfileSettings(profileSettings *ProfileSettings) error {
    tree, err := loadConfigFile()
    if err != nil {
        return err
    }

    prefix := asProfileKey(*profileSettings.ProfileName) + "."
    if err := setString(tree, prefix+profileKeyProfileType, profileSettings.ProfileType); err != nil {
        return err
    }
    if err := setString(tree, prefix+profileKeyUser, profileSettings.User); err != nil {
        return err
    }

    // Okta

    if profileSettings.Okta != nil {
        if err := setString(tree, prefix+profileKeyOktaURL, profileSettings.Okta.URL); err != nil {
            return err
        }
        if err := setString(tree, prefix+profileKeyOktaAppURL, profileSettings.Okta.AppURL); err != nil {
            return err
        }
        if err := setString(tree, prefix+profileKeyOktaAuthMethod, profileSettings.Okta.AuthMethod); err != nil {
            return err
        }
    }

    // Auth0

    if profileSettings.Auth0 != nil {
        if err := setString(tree, prefix+profileKeyAuth0URL, profileSettings.Auth0.URL); err != nil {
            return err
        }
        if err := setString(tree, prefix+profileKeyAuth0AuthMethod, profileSettings.Auth0.AuthMethod); err != nil {
            return err
        }
        if err := setString(tree, prefix+profileKeyAuth0ClientId, profileSettings.Auth0.ClientId); err != nil {
            return err
        }
        if err := setString(tree, prefix+profileKeyAuth0ClientSecret, profileSettings.Auth0.ClientSecret); err != nil {
            return err
        }
    }

    // AWS

    if err := setString(tree, prefix+profileKeyRole, profileSettings.AwsRole); err != nil {
        return err
    }
    if err := setInt(tree, prefix+profileKeySessionTime, profileSettings.AwsSessionTime); err != nil {
        return err
    }

    return storeConfigFile(tree)
}

func DeleteProfileSettings(profileName string) error {
    tree, err := loadConfigFile()
    if err != nil {
        return err
    }

    if err := tree.Delete(asProfileKey(profileName)); err != nil {
        return nil
    }
    return storeConfigFile(tree)
}

func SelectProfile(flags *pflag.FlagSet) *ProfileSettings {

    flagConfigProvider := newFlagConfigProvider(flags, false)

    profile := evaluateString(labelProfile,
        flagConfigProvider(FlagProfile), // --profile flag
        profileMenu(false))

    if profile == nil {
        return nil
    }

    _, p := ListProfiles()
    for k := range p {
        if k == *profile {
            return p[*profile]
        }
    }

    return nil
}

func NewProfileName(flags *pflag.FlagSet) (*ProfileSettings, error) {

    flagConfigProvider := newFlagConfigProvider(flags, false)

    profileName := evaluateString(labelProfile,
        flagConfigProvider(FlagProfile), // --profile flag
        interactiveStringValue(labelProfile, nil, nil))

    if profileName == nil {
        return nil, fmt.Errorf("No profile name given")
    }

    _, p := ListProfiles()
    for k := range p {
        if k == *profileName {
            return nil, fmt.Errorf("Profile '%s' already exists!", k)
        }
    }

    return &ProfileSettings{ProfileName: profileName}, nil
}

func newProfileConfigProvider(profileName string) configKey {
    if *globalNoConfig {
        return newNullConfigProvider()
    }

    store := store.Sub(asProfileKey(profileName))
    if store == nil {
        // no such key exists
        store = viper.New()
    }

    return func(field string) configProvider {
        return &StoreConfigProvider{store, field, fmt.Sprintf("profile [%s]", profileName)}
    }
}

func isProfileKey(key string) bool {
    return strings.HasPrefix(key, profilePrefix)
}

func asProfileKey(key string) string {
    return profilePrefix + key
}

func stripProfileKey(key string) (*string, bool) {
    if isProfileKey(key) {
        return toSP(strings.TrimPrefix(key, profilePrefix)), true
    }
    return nil, false
}

func profilePrompt(profileName *string, prompt string) string {
    if profileName != nil {
        return prompt
    }

    return "Default " + prompt
}

func loadProfile(s *viper.Viper, profileName *string) *ProfileSettings {
    p := &ProfileSettings{ProfileName: profileName}

    p.Okta = &OktaProfileSettings{}
    p.Auth0 = &Auth0ProfileSettings{}

    if s != nil {
        p.ProfileName = profileName
        p.ProfileType = getString(s, profileKeyProfileType)
        p.User = getString(s, profileKeyUser)

        // Okta

        p.Okta.AuthMethod = getString(s, profileKeyOktaAuthMethod)
        p.Okta.URL = getString(s, profileKeyOktaURL)
        p.Okta.AppURL = getString(s, profileKeyOktaAppURL)

        // auth0

        p.Auth0.URL = getString(s, profileKeyAuth0URL)
        p.Auth0.AuthMethod = getString(s, profileKeyAuth0AuthMethod)
        p.Auth0.ClientId = getString(s, profileKeyAuth0ClientId)
        p.Auth0.ClientSecret = getString(s, profileKeyAuth0ClientSecret)

        // AWS

        p.AwsRole = getString(s, profileKeyRole)
        p.AwsSessionTime = getInt(s, profileKeySessionTime)
    }
    return p
}

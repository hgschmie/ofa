package ofa

import (
    "fmt"
    "strings"

    "github.com/spf13/pflag"
    "github.com/spf13/viper"
)

type ProfileSettings struct {
    ProfileName    *string
    OktaAppURL     *string `validate:"omitempty,url"`
    OktaAuthMethod *string `validate:"omitempty,oneof=token sms push"`
    OktaUser       *string
    OktaURL        *string `validate:"omitempty,url"`
    AwsRole        *string
    AwsSessionTime *int64 `validate:"omitempty,gte=3600,lte=86400"`
}

func (p *ProfileSettings) Display(profileName *string) {
    if profileName != nil {
        Information("")
        Information("**** Profile [%s] settings:", *profileName)
    } else {
        logStringSetting(profilePrompt(profileName, labelProfile), p.ProfileName)
    }
    logStringSetting(profilePrompt(profileName, labelUser), p.OktaUser)
    logStringSetting(profilePrompt(profileName, labelAuthMethod), p.OktaAuthMethod)
    logStringSetting(profilePrompt(profileName, labelOktaURL), p.OktaURL)
    logStringSetting(profilePrompt(profileName, labelOktaAppURL), p.OktaAppURL)
    logStringSetting(profilePrompt(profileName, labelRole), p.AwsRole)
    logIntSetting(profilePrompt(profileName, labelSessionTime), p.AwsSessionTime)
}

func ListProfiles() (*DefaultSettings, map[string]*ProfileSettings) {
    d := &DefaultSettings{}
    p := map[string]*ProfileSettings{}

    if !*globalNoConfig {

        d.Verbose = getBool(store, globalKeyVerbose)
        d.Interactive = getBool(store, globalKeyInteractive)
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

    profileSettings.ProfileName = evaluateString(labelProfile,
        flagConfigProvider(FlagSetProfile),
        interactiveStringValue(profilePrompt(rootProfileName, promptProfile), defaultSettings.ProfileName, nil))

    profileSettings.OktaUser = evaluateString(labelUser,
        flagConfigProvider(FlagSetUser),
        interactiveStringValue(profilePrompt(profileSettings.ProfileName, promptUser), defaultSettings.OktaUser, nil))

    profileSettings.OktaURL = evaluateString(labelOktaURL,
        flagConfigProvider(FlagSetOktaURL),
        interactiveStringValue(profilePrompt(profileSettings.ProfileName, promptOktaURL), defaultSettings.OktaURL, validateURL))

    profileSettings.OktaAppURL = evaluateString(labelOktaAppURL,
        flagConfigProvider(FlagSetOktaAppURL),
        interactiveStringValue(profilePrompt(profileSettings.ProfileName, promptOktaAppURL), defaultSettings.OktaAppURL, validateURL))

    profileSettings.OktaAuthMethod = evaluateString(labelAuthMethod,
        flagConfigProvider(FlagSetAuthMethod),
        interactiveMenu(profilePrompt(profileSettings.ProfileName, promptAuthMethod), authMethods, defaultSettings.OktaAuthMethod))

    profileSettings.AwsRole = evaluateString(labelRole,
        flagConfigProvider(FlagSetRole),
        interactiveStringValue(profilePrompt(profileSettings.ProfileName, promptRole), defaultSettings.AwsRole, nil))

    profileSettings.AwsSessionTime = evaluateInt(labelSessionTime,
        flagConfigProvider(FlagSetSessionTime),
        interactiveIntValue(profilePrompt(profileSettings.ProfileName, promptSessionTime), defaultSettings.AwsSessionTime))

    if err := validate.Struct(profileSettings); err != nil {
        return nil, err
    }

    return profileSettings, nil
}

func StoreProfileSettings(profileSettings *ProfileSettings) error {
    tree, err := loadConfigFile()
    if err != nil {
        return err
    }

    prefix := asProfileKey(*profileSettings.ProfileName) + "."
    if err := setString(tree, prefix+profileKeyUser, profileSettings.OktaUser); err != nil {
        return err
    }
    if err := setString(tree, prefix+profileKeyOktaURL, profileSettings.OktaURL); err != nil {
        return err
    }
    if err := setString(tree, prefix+profileKeyOktaAppURL, profileSettings.OktaAppURL); err != nil {
        return err
    }
    if err := setString(tree, prefix+profileKeyAuthMethod, profileSettings.OktaAuthMethod); err != nil {
        return err
    }
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
        profileMenu())

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
        interactiveStringValue(promptProfile, nil, nil))

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

    if s != nil {
        p.ProfileName = profileName
        p.OktaUser = getString(s, profileKeyUser)
        p.OktaAuthMethod = getString(s, profileKeyAuthMethod)
        p.OktaURL = getString(s, profileKeyOktaURL)
        p.OktaAppURL = getString(s, profileKeyOktaAppURL)
        p.AwsRole = getString(s, profileKeyRole)
        p.AwsSessionTime = getInt(s, profileKeySessionTime)
    }
    return p
}

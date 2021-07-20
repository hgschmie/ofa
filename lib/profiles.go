package ofa

import (
    "fmt"
    "strings"

    "github.com/pelletier/go-toml"
    log "github.com/sirupsen/logrus"
    "github.com/spf13/pflag"
    "github.com/spf13/viper"
)

type ProfileSettings struct {
    ProfileName     *string
    ProfileType     *string `validate:"omitempty,oneof=okta auth0"`
    User            *string
    AwsRole         *string
    AwsSessionTime  *int64 `validate:"omitempty,gte=3600,lte=86400"`
    profileSettings map[string]interface{}
    providers       map[string]providerProfile
}

func createProfileSettings(profileName *string, profileType *string) (*ProfileSettings, error) {
    profile := &ProfileSettings{
        ProfileName: profileName,
    }

    if err := profile.updateProfileType(profileType); err != nil {
        return nil, err
    }

    return profile, nil
}

func (p *ProfileSettings) updateProfileType(profileType *string) error {
    p.ProfileType = profileType
    p.providers = make(map[string]providerProfile)
    if p.ProfileType == nil {
        for name, v := range providerTypes {
            p.providers[name] = v.Create()
        }
    } else {
        if provider, ok := providerTypes[*p.ProfileType]; ok {
            p.providers[*p.ProfileType] = provider.Create()
        } else {
            return fmt.Errorf("Profile type '%v' for profile '%v' is unknown!", p.ProfileType, p.ProfileName)
        }
    }

    return nil
}

var (
    profileTypeOkta  = toSP("okta")
    profileTypeAuth0 = toSP("auth0")

    profileTypes = map[string]*string{
        "Okta":  profileTypeOkta,
        "Auth0": profileTypeAuth0,
    }

    providerTypes = map[string]providerProfile{
        "okta":  &OktaProfileSettings{},
        "auth0": &Auth0ProfileSettings{},
    }
)

type providerProfile interface {
    Create() providerProfile
    Validate() error
    Log(profileName *string)
    Prompt(rootProfileName *string, flagConfigProvider ConfigProvider, defaultSettings map[string]interface{}) error
    Load(profileSettings map[string]interface{}) error
    Store(tree *toml.Tree, prefix string) error
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

    for _, provider := range p.providers {
        //err := provider.Load(p.profileSettings)
        //if err != nil {
        //    log.Fatalf("Could not load settings for '%v' in profile '%v': %v", name, profileName, err)
        //}

        provider.Log(profileName)
    }

    logStringSetting(profilePrompt(profileName, labelRole), p.AwsRole)
    logIntSetting(profilePrompt(profileName, labelSessionTime), p.AwsSessionTime)
}

func ListProfiles() (*DefaultSettings, map[string]ProfileSettings) {

    d := &DefaultSettings{}
    p := map[string]ProfileSettings{}

    if !*globalNoConfig {

        d.Verbose = getBool(store, globalKeyVerbose)
        d.Interactive = getBool(store, globalKeyInteractive)
        // load the profile defaults
        d.Profile = *loadProfile(store, getString(store, globalKeyProfile))

        for k := range store.AllSettings() {
            if profile, ok := stripProfileKey(k); ok {
                substore := store.Sub(k)
                p[*profile] = *loadProfile(substore, profile)
            }
        }
    }

    return d, p
}

func CreateProfileSettings(flags *pflag.FlagSet, rootProfileName *string, defaultSettings ProfileSettings) (*ProfileSettings, error) {
    profileSettings, err := createProfileSettings(defaultSettings.ProfileName, nil)
    if err != nil {
        return nil, err
    }

    flagConfigProvider := newFlagConfig(flags, false)

    profileType := evaluateString(labelProfileType,
        flagConfigProvider(FlagSetProfileType),
        interactiveMenu(profilePrompt(rootProfileName, labelProfileType), profileTypes, defaultSettings.ProfileType))

    // root profile can have defaults for all profiles, anything else has only a single profile
    if err := profileSettings.updateProfileType(profileType); err != nil {
        return nil, err
    }

    profileSettings.User = evaluateString(labelUser,
        flagConfigProvider(FlagSetUser),
        interactiveStringValue(profilePrompt(rootProfileName, labelUser), defaultSettings.User, nil))

    // login providers

    for _, v := range profileSettings.providers {
        err := v.Prompt(rootProfileName, flagConfigProvider, defaultSettings.profileSettings)
        if err != nil {
            return nil, err
        }
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

    for _, v := range profileSettings.providers {
        err := v.Validate()
        if err != nil {
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

    // providers
    for _, v := range profileSettings.providers {
        if err := v.Store(tree, prefix); err != nil {
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

    flagConfigProvider := newFlagConfig(flags, false)

    profile := evaluateString(labelProfile,
        flagConfigProvider(FlagProfile), // --profile flag
        profileMenu(false))

    if profile == nil {
        return nil
    }

    _, p := ListProfiles()
    for k := range p {
        if k == *profile {
            x := p[*profile]
            return &x
        }
    }

    return nil
}

func NewProfileName(flags *pflag.FlagSet) (*ProfileSettings, error) {

    flagConfigProvider := newFlagConfig(flags, false)

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

    return createProfileSettings(profileName, nil)
}

func newProfileConfigProvider(profileName string) ConfigProvider {
    if *globalNoConfig {
        return newNullConfig()
    }

    store := store.Sub(asProfileKey(profileName))
    if store == nil {
        // no such key exists
        store = viper.New()
    }

    return func(field string) configField {
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

    var profileType *string
    if s != nil {
        profileType = getString(s, profileKeyProfileType)
    }

    p, err := createProfileSettings(profileName, profileType)
    if err != nil {
        log.Fatalf("Could not load profile '%v': %v", profileName, err)
    }

    if s != nil {
        p.User = getString(s, profileKeyUser)
        p.profileSettings = s.AllSettings()

        for name, v := range p.providers {
            err := v.Load(p.profileSettings)
            if err != nil {
                log.Panicf("Could not load settings for '%v' in profile '%v': %v", name, profileName, err)
            }
        }

        // AWS

        p.AwsRole = getString(s, profileKeyRole)
        p.AwsSessionTime = getInt(s, profileKeySessionTime)
    }
    return p
}

package ofa

import (
    "github.com/spf13/pflag"
)

type DefaultSettings struct {
    Verbose     *bool
    Interactive *bool
    Profile     ProfileSettings
}

func (g *DefaultSettings) Display() {
    Information("**** Default settings:")

    logBoolSetting(labelVerbose, g.Verbose)
    logBoolSetting(labelInteractive, g.Interactive)

    g.Profile.Display(nil)
}

func CreateDefaultSettings(flags *pflag.FlagSet) (*DefaultSettings, error) {

    defaultSettings, _ := ListProfiles()

    globalSettings := &DefaultSettings{}

    flagConfigProvider := newFlagConfigProvider(flags, false)

    globalSettings.Verbose, _ = evaluateBool(labelVerbose,
        flagConfigProvider(FlagSetVerbose),
        interactiveBoolValue("Default verbose setting", defaultSettings.Verbose))

    globalSettings.Interactive, _ = evaluateBool(labelInteractive,
        flagConfigProvider(FlagSetInteractive),
        interactiveBoolValue("Default interactive setting", defaultSettings.Interactive))

    defaultSettings.Profile.ProfileName = evaluateString(labelProfile,
        flagConfigProvider(FlagSetProfile),
        interactiveStringValue(profilePrompt(nil, labelProfile), defaultSettings.Profile.ProfileName, nil))

    profileSettings, err := CreateProfileSettings(flags, nil, defaultSettings.Profile)
    if err != nil {
        return nil, err
    }

    globalSettings.Profile = *profileSettings
    return globalSettings, nil
}

func StoreDefaultSettings(globalSettings *DefaultSettings) error {
    tree, err := loadConfigFile()
    if err != nil {
        return err
    }

    if err := setBool(tree, globalKeyVerbose, globalSettings.Verbose); err != nil {
        return err
    }
    if err := setBool(tree, globalKeyInteractive, globalSettings.Interactive); err != nil {
        return err
    }
    if err := setString(tree, globalKeyProfile, globalSettings.Profile.ProfileName); err != nil {
        return err
    }
    if err := setString(tree, profileKeyProfileType, globalSettings.Profile.ProfileType); err != nil {
        return err
    }
    if err := setString(tree, profileKeyUser, globalSettings.Profile.User); err != nil {
        return err
    }

    // Okta

    if err := setString(tree, profileKeyOktaURL, globalSettings.Profile.Okta.URL); err != nil {
        return err
    }
    if err := setString(tree, profileKeyOktaAppURL, globalSettings.Profile.Okta.AppURL); err != nil {
        return err
    }
    if err := setString(tree, profileKeyOktaAuthMethod, globalSettings.Profile.Okta.AuthMethod); err != nil {
        return err
    }

    // Auth0

    if err := setString(tree, profileKeyAuth0URL, globalSettings.Profile.Auth0.URL); err != nil {
        return err
    }
    if err := setString(tree, profileKeyAuth0AuthMethod, globalSettings.Profile.Auth0.AuthMethod); err != nil {
        return err
    }
    if err := setString(tree, profileKeyAuth0ClientId, globalSettings.Profile.Auth0.ClientId); err != nil {
        return err
    }
    if err := setString(tree, profileKeyAuth0ClientSecret, globalSettings.Profile.Auth0.ClientSecret); err != nil {
        return err
    }

    // AWS

    if err := setString(tree, profileKeyRole, globalSettings.Profile.AwsRole); err != nil {
        return err
    }
    if err := setInt(tree, profileKeySessionTime, globalSettings.Profile.AwsSessionTime); err != nil {
        return err
    }

    return storeConfigFile(tree)
}

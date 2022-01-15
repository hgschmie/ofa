package ofa

import (
	"fmt"
	"github.com/spf13/pflag"
)

type DefaultSettings struct {
	Verbose     *bool
	Interactive *bool
	Profile     ProfileSettings
}

func (g *DefaultSettings) Display() {
	fmt.Println("**** Default settings:")

	displayBoolSetting(labelVerbose, g.Verbose)
	displayBoolSetting(labelInteractive, g.Interactive)

	g.Profile.Display(nil)
}

func CreateDefaultSettings(flags *pflag.FlagSet) (*DefaultSettings, error) {

	defaultSettings, _ := ListProfiles()

	globalSettings := &DefaultSettings{}

	flagConfigProvider := newFlagConfig(flags, false)

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
	tree, err := configStore.loadConfigFile()
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
	if err := setString(tree, profileKeyURL, globalSettings.Profile.URL); err != nil {
		return err
	}

	for _, v := range globalSettings.Profile.identityProviders {
		if err := v.Store(tree, ""); err != nil {
			return err
		}
	}

	// AWS

	if err := setString(tree, profileKeyAwsAccount, globalSettings.Profile.AwsAccount); err != nil {
		return err
	}
	if err := setString(tree, profileKeyAwsRole, globalSettings.Profile.AwsRole); err != nil {
		return err
	}
	if err := setInt(tree, profileKeySessionTime, globalSettings.Profile.AwsSessionTime); err != nil {
		return err
	}

	return configStore.storeConfigFile(tree)
}

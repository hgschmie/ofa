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
	ProfileName       *string
	ProfileType       *string `validate:"omitempty,oneof=okta auth0 onelogin"`
	URL               *string `validate:"omitempty,url"`
	User              *string `validate:"omitempty"`
	AwsAccount        *string `validate:"omitempty"`
	AwsRole           *string `validate:"omitempty"`
	AwsSessionTime    *int64  `validate:"omitempty,gte=3600,lte=86400"`
	identityProviders map[string]IdpProfile
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
	p.identityProviders = make(map[string]IdpProfile)

	if profileType == nil || p.ProfileName == nil {
		for name, v := range idpProfiles {
			p.identityProviders[name] = v.Create()
		}
	} else {
		if provider, ok := idpProfiles[*profileType]; ok {
			p.identityProviders[*profileType] = provider.Create()
		} else {
			return fmt.Errorf("Profile type '%v' for profile '%v' is unknown!", p.ProfileType, p.ProfileName)
		}
	}

	return nil
}

type IdpProfile interface {
	Create() IdpProfile
	Validate() error
	Log(profileName *string)
	Prompt(rootProfileName *string, flagConfigProvider ConfigProvider, identityProviders map[string]IdpProfile) error
	Load(s *viper.Viper)
	Store(tree *toml.Tree, prefix string) error
}

func (p *ProfileSettings) Display(profileName *string) {
	if profileName != nil {
		// actual profile
		fmt.Println("")

		fmt.Printf("**** Profile [ %s ] settings:\n", *profileName)

		displayStringSetting(profilePrompt(profileName, labelProfileType), p.ProfileType)

	} else {
		// global settings
		displayStringSetting(profilePrompt(profileName, labelProfile), p.ProfileName)
	}
	displayStringSetting(profilePrompt(profileName, labelUser), p.User)
	displayStringSetting(profilePrompt(profileName, labelURL), p.URL)

	for _, provider := range p.identityProviders {
		provider.Log(profileName)
	}

	displayStringSetting(profilePrompt(profileName, labelAwsAccount), p.AwsAccount)
	displayStringSetting(profilePrompt(profileName, labelAwsRole), p.AwsRole)
	displayIntSetting(profilePrompt(profileName, labelSessionTime), p.AwsSessionTime)
}

func ListProfiles() (*DefaultSettings, map[string]ProfileSettings) {

	d := &DefaultSettings{}
	p := map[string]ProfileSettings{}

	if !*globalNoConfig {

		d.Verbose = getBool(configStore.store, globalKeyVerbose)
		d.Interactive = getBool(configStore.store, globalKeyInteractive)
		// load the profile defaults
		d.Profile = *loadProfile(configStore.store, nil)
		d.Profile.ProfileName = getString(configStore.store, globalKeyProfile)

		for k := range configStore.store.AllSettings() {
			if profile, ok := stripProfileKey(k); ok {
				substore := configStore.store.Sub(k)
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
		interactiveMenu(profilePrompt(rootProfileName, labelProfileType), availableIdp, defaultSettings.ProfileType))

	if rootProfileName == nil {
		profileSettings.ProfileType = profileType
	} else {
		// collapse profile settings to the provider type, for the root
		// all providers are prompted
		if err := profileSettings.updateProfileType(profileType); err != nil {
			return nil, err
		}
	}

	profileSettings.User = evaluateString(labelUser,
		flagConfigProvider(FlagSetUser),
		interactiveStringValue(profilePrompt(rootProfileName, labelUser), defaultSettings.User, nil))

	profileSettings.URL = evaluateString(labelURL,
		flagConfigProvider(FlagSetURL),
		interactiveStringValue(profilePrompt(rootProfileName, labelURL), defaultSettings.URL, validateURL))

	// login providers

	for _, v := range profileSettings.identityProviders {
		err := v.Prompt(rootProfileName, flagConfigProvider, defaultSettings.identityProviders)
		if err != nil {
			return nil, err
		}
	}

	// AWS

	profileSettings.AwsAccount = evaluateString(labelAwsAccount,
		flagConfigProvider(FlagSetAwsAccount),
		interactiveStringValue(profilePrompt(rootProfileName, labelAwsAccount), defaultSettings.AwsAccount, nil))

	profileSettings.AwsRole = evaluateString(labelAwsRole,
		flagConfigProvider(FlagSetAwsRole),
		interactiveStringValue(profilePrompt(rootProfileName, labelAwsRole), defaultSettings.AwsRole, nil))

	profileSettings.AwsSessionTime = evaluateInt(labelSessionTime,
		flagConfigProvider(FlagSetSessionTime),
		interactiveIntValue(profilePrompt(rootProfileName, labelSessionTime), defaultSettings.AwsSessionTime))

	if err := validate.Struct(profileSettings); err != nil {
		return nil, err
	}

	for _, v := range profileSettings.identityProviders {
		err := v.Validate()
		if err != nil {
			return nil, err
		}
	}

	return profileSettings, nil
}

func StoreProfileSettings(profileSettings *ProfileSettings) error {
	tree, err := configStore.loadConfigFile()
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

	if err := setString(tree, prefix+profileKeyURL, profileSettings.URL); err != nil {
		return err
	}

	// providers
	for _, v := range profileSettings.identityProviders {
		if err := v.Store(tree, prefix); err != nil {
			return err
		}
	}

	// AWS

	if err := setString(tree, prefix+profileKeyAwsAccount, profileSettings.AwsAccount); err != nil {
		return err
	}
	if err := setString(tree, prefix+profileKeyAwsRole, profileSettings.AwsRole); err != nil {
		return err
	}
	if err := setInt(tree, prefix+profileKeySessionTime, profileSettings.AwsSessionTime); err != nil {
		return err
	}

	return configStore.storeConfigFile(tree)
}

func DeleteProfileSettings(profileName string) error {
	tree, err := configStore.loadConfigFile()
	if err != nil {
		return err
	}

	if err := tree.Delete(asProfileKey(profileName)); err != nil {
		return nil
	}
	return configStore.storeConfigFile(tree)
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

	store := configStore.subStore(asProfileKey(profileName))

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

		p.URL = getString(s, profileKeyURL)

		for _, v := range p.identityProviders {
			v.Load(s)
		}

		// AWS

		p.AwsAccount = getString(s, profileKeyAwsAccount)
		p.AwsRole = getString(s, profileKeyAwsRole)
		p.AwsSessionTime = getInt(s, profileKeySessionTime)
	}
	return p
}

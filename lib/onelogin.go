package ofa

import (
    "github.com/pelletier/go-toml"
    log "github.com/sirupsen/logrus"
    "github.com/spf13/pflag"
    "github.com/spf13/viper"
)

/*
 * Onelogin logic
 */

type OneloginIdentityProvider struct {
    config *LoginSession
}

func (p *OneloginIdentityProvider) name() string {
    return "Onelogin"
}

func (p *OneloginIdentityProvider) providerProfile() IdpProfile {
    return &OneloginProfileSettings{}
}

func (p *OneloginIdentityProvider) DefaultFlags(flags *pflag.FlagSet) {
}

func (p *OneloginIdentityProvider) LoginFlags(flags *pflag.FlagSet) {
}

func (p *OneloginIdentityProvider) ProfileFlags(flags *pflag.FlagSet) {
}

func (p *OneloginIdentityProvider) Configure(config *LoginSession) error {
    p.config = config

    return validate.Struct(p)
}

func (p *OneloginIdentityProvider) Validate() error {
    return nil
}

func (p *OneloginIdentityProvider) Login() (*string, error) {

    Information("**** Logging into Onelogin")

    return nil, nil
}

func (p *OneloginIdentityProvider) InitiateSession(sessionToken string) (samlResponse *string, err error) {
    return nil, nil
}

type OneloginProfileSettings struct {
}

//
// Profile settings
//

func (p *OneloginProfileSettings) Create() IdpProfile {
    return &OneloginProfileSettings{}
}

func (p *OneloginProfileSettings) Validate() error {
    return validate.Struct(p)
}

func (p *OneloginProfileSettings) Log(profileName *string) {
}

func (p *OneloginProfileSettings) Prompt(rootProfileName *string, flagConfigProvider ConfigProvider, identityProviders map[string]IdpProfile) error {

    var defaults *OneloginProfileSettings

    if defaultSettings, ok := identityProviders[oneloginName]; ok {
        defaults = defaultSettings.(*OneloginProfileSettings)
    } else {
        defaults = p.Create().(*OneloginProfileSettings)
    }

    log.Debugf("%v", defaults)

    return nil
}

func (p *OneloginProfileSettings) Load(s *viper.Viper) {
}

func (p *OneloginProfileSettings) Store(tree *toml.Tree, prefix string) error {
    return nil
}

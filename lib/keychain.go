package ofa

import (
    "fmt"
    "net/url"

    "github.com/keybase/go-keychain"
    log "github.com/sirupsen/logrus"
    "github.com/spf13/pflag"
)

func init() {
}

const accessGroup = "ofa_OKTA_PASSWORD"

type KeychainPassword struct {
    URL      *url.URL `validate:"required,url"`
    User     string   `validate:"required"`
    Password *string
}

func NewKeychainPassword(flags *pflag.FlagSet, promptForPassword bool) (*KeychainPassword, error) {

    keychainEntry := &KeychainPassword{}

    rootConfigProvider := defaultConfigProvider()
    flagConfigProvider := newFlagConfigProvider(flags, false)

    profileName := evaluateString(labelProfile,
        flagConfigProvider(FlagProfile),      // --profile flag
        rootConfigProvider(globalKeyProfile), // root level configuration key "profile"
        profileMenu())

    profileConfigProvider := newNullConfigProvider()

    if profileName != nil {
        profileConfigProvider = newProfileConfigProvider(*profileName)
    }

    var err error

    keychainEntry.URL, err = getURL(evaluateString(labelOktaURL,
        flagConfigProvider(FlagOktaURL),
        profileConfigProvider(profileKeyOktaURL),
        rootConfigProvider(profileKeyOktaURL),
        interactiveStringValue(promptOktaURL, nil, validateURL)))

    if err != nil {
        return nil, err
    }

    user := evaluateString(labelUser,
        flagConfigProvider(FlagUser),          // --user flag
        profileConfigProvider(profileKeyUser), // profile level configuration key "okta_user"
        rootConfigProvider(profileKeyUser),    // global configuration key "okta_user"
        interactiveStringValue(promptUser, nil, nil)) // interactive prompt

    if user == nil {
        return nil, fmt.Errorf("No user name given!")
    }

    keychainEntry.User = *user

    if promptForPassword {
        keychainEntry.Password = evaluateMask(labelPassword,
            flagConfigProvider(FlagPassword), // --password flag
            interactivePasswordValue(promptPassword+" (Press ENTER to delete)")) // interactive prompt
    }

    if err := validate.Struct(keychainEntry); err != nil {
        return nil, err
    }

    return keychainEntry, nil
}

func (p *KeychainPassword) Delete() error {
    serviceUrl := p.URL.String()

    err := keychain.DeleteGenericPasswordItem(serviceUrl, p.User)
    if keychainError, ok := err.(keychain.Error); ok {
        if keychainError == keychain.ErrorItemNotFound { // not found is ok
            return nil
        }
    }
    return err
}

func (p *KeychainPassword) Update() error {
    serviceUrl := p.URL.String()

    if p.Password == nil || len(*p.Password) == 0 {
        return fmt.Errorf("Password can not be empty!")
    }
    item := keychain.NewGenericPassword(
        serviceUrl,
        p.User,
        fmt.Sprintf("Okta password for %s @ %s", p.User, serviceUrl),
        []byte(*p.Password),
        accessGroup)
    item.SetSynchronizable(keychain.SynchronizableNo)
    item.SetAccessible(keychain.AccessibleWhenUnlocked)

    err := keychain.AddItem(item)
    if keychainError, ok := err.(keychain.Error); ok {
        if keychainError == keychain.ErrorDuplicateItem {
            err = p.Delete()
            if err != nil {
                return err
            }
            err = keychain.AddItem(item)
        }
    }
    return err
}

func (p *KeychainPassword) location() string {
    return fmt.Sprintf("Keychain for Okta URL '%s', username '%s'", p.URL, p.User)
}

func (p *KeychainPassword) stringValue() (*string, string) {
    if p.URL == nil {
        return nil, ""
    }

    query := keychain.NewItem()
    query.SetSecClass(keychain.SecClassGenericPassword)
    query.SetService(p.URL.String())
    query.SetAccount(p.User)
    query.SetAccessGroup(accessGroup)
    query.SetMatchLimit(keychain.MatchLimitOne)
    query.SetSynchronizable(keychain.SynchronizableAny)
    query.SetReturnData(true)
    results, err := keychain.QueryItem(query)

    if err != nil {
        return nil, ""
    }

    if len(results) < 1 {
        return nil, ""
    }

    return toSP(string(results[0].Data)), p.location()
}

func (p *KeychainPassword) intValue() (*int64, string) {
    log.Fatal("Not implemented")
    return nil, ""
}

func (p *KeychainPassword) boolValue() (*bool, string) {
    log.Fatal("Not implemented")
    return nil, ""
}

func newKeychainEntry(url *url.URL) configKey {
    return func(username string) configProvider {
        return &KeychainPassword{URL: url, User: username}
    }
}

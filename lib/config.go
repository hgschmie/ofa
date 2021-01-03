package ofa

import (
    "fmt"
    "strconv"

    "github.com/manifoldco/promptui"
    log "github.com/sirupsen/logrus"
    "github.com/spf13/pflag"
)

//
// config providers get plugged together to provide a specific setting either
// from configuration, flags or interactive input.
//

type configProvider interface {
    stringValue() (*string, string)
    intValue() (*int64, string)
    boolValue() (*bool, string)
}

type configKey func(field string) configProvider

// return a configured string value
func evaluateString(label string, cp ...configProvider) *string {
    for _, c := range cp {
        if value, source := c.stringValue(); value != nil {
            if *globalVerbose && len(label) > 0 {
                log.Infof("%s %s (%s)", padLabel(label), *value, source)
            }
            return value
        }
    }
    return nil
}

func evaluateMask(label string, cp ...configProvider) *string {
    for _, c := range cp {
        if value, source := c.stringValue(); value != nil {
            if *globalVerbose && len(label) > 0 {
                log.Infof("%s <configured> (%s)", padLabel(label), source)
            }
            return value
        }
    }
    return nil
}

// return a configured integer value
func evaluateInt(label string, cp ...configProvider) *int64 {
    for _, c := range cp {
        if value, source := c.intValue(); value != nil {
            if *globalVerbose && len(label) > 0 {
                log.Infof("%s %d (%s)", padLabel(label), *value, source)
            }
            return value
        }
    }
    return nil
}

// return a configured boolean value
func evaluateBool(label string, cp ...configProvider) (*bool, string) {
    for _, c := range cp {
        if value, source := c.boolValue(); value != nil {
            if *globalVerbose && len(label) > 0 {
                log.Infof("%s %t (%s)", padLabel(label), *value, source)
            }
            return value, source

        }
    }
    return nil, ""
}

//
// Flag Config gives access to the pflag flags
//
type flagConfigProvider struct {
    flags    *pflag.FlagSet
    flagname string
    negate   bool
}

func (p *flagConfigProvider) location() string {
    return fmt.Sprintf("flag: '%s'", p.flagname)
}

func (p *flagConfigProvider) stringValue() (*string, string) {
    if p.flags.Changed(p.flagname) {
        return toSPError(p.flags.GetString(p.flagname)), p.location()
    }
    return nil, ""
}

func (p *flagConfigProvider) intValue() (*int64, string) {
    if p.flags.Changed(p.flagname) {
        return toIPError(p.flags.GetInt64(p.flagname)), p.location()
    }
    return nil, ""
}

func (p *flagConfigProvider) boolValue() (*bool, string) {
    if p.flags.Changed(p.flagname) {
        v, err := p.flags.GetBool(p.flagname)
        return toBPError(v != p.negate, err), // this is v ^ p.negate, golang style. Surprisingly annoying
            p.location()
    }
    return nil, ""
}

func newFlagConfigProvider(flags *pflag.FlagSet, negate bool) configKey {
    return func(flagname string) configProvider {
        return &flagConfigProvider{flags, flagname, negate}
    }
}

//
// Null Config always return nil for any config key
//
type nullConfigProvider struct {
}

func (p *nullConfigProvider) stringValue() (*string, string) {
    return nil, ""
}

func (p *nullConfigProvider) intValue() (*int64, string) {
    return nil, ""
}

func (p *nullConfigProvider) boolValue() (*bool, string) {
    return nil, ""
}

func newNullConfigProvider() configKey {
    return func(field string) configProvider {
        return &nullConfigProvider{}
    }
}

//
// Default Config always return a default value
//
type defaultValueProvider struct {
    defaultString *string
    defaultBool   *bool
}

func (p *defaultValueProvider) location() string {
    return "default value"
}

func (p *defaultValueProvider) stringValue() (*string, string) {
    return p.defaultString, p.location()
}

func (p *defaultValueProvider) intValue() (*int64, string) {
    log.Fatal("Not implemented")
    return nil, ""
}

func (p *defaultValueProvider) boolValue() (*bool, string) {
    return p.defaultBool, p.location()
}

func defaultStringValue(defaultString string) configProvider {
    return &defaultValueProvider{defaultString: &defaultString}
}

func defaultBoolValue(defaultBool bool) configProvider {
    return &defaultValueProvider{defaultBool: &defaultBool}
}

//
// Prompt Config prompts for user input.
//
type promptConfigProvider struct {
    label              string
    hidden             bool
    defaultStringValue *string
    defaultIntValue    *int64
    defaultBoolValue   *bool
    validate           promptui.ValidateFunc
}

func (p *promptConfigProvider) location(isDefault bool) string {
    if isDefault {
        return "user input (default value auto-selected)"
    }

    return "user input"
}

func (p *promptConfigProvider) stringValue() (*string, string) {

    value, err := textInput(p.label, p.defaultStringValue, p.hidden, p.validate)
    if err != nil || len(*value) == 0 {
        return nil, ""
    }
    return value, p.location(p.defaultStringValue == value)
}

func (p *promptConfigProvider) intValue() (*int64, string) {
    var defaultValue *string = nil
    if p.defaultIntValue != nil {
        defaultValue = toSP(strconv.FormatInt(*p.defaultIntValue, 10))
    }

    value, err := textInput(p.label, defaultValue, false, validateNumber)
    if err != nil || len(*value) == 0 {
        return nil, ""
    }

    return toIPError(strconv.ParseInt(*value, 10, 64)),
        p.location(defaultValue == value) // pointer compare!
}

func (p *promptConfigProvider) boolValue() (*bool, string) {
    var defaultValue *string = nil
    if p.defaultBoolValue != nil {
        defaultValue = toSP(strconv.FormatBool(*p.defaultBoolValue))
    }

    value, err := textInput(p.label, defaultValue, false, validateBool)
    if err != nil || len(*value) == 0 {
        return nil, ""
    }

    return toBPError(strconv.ParseBool(*value)),
        p.location(defaultValue == value) // pointer compare!
}

func interactiveStringValue(label string, defaultValue *string, validate promptui.ValidateFunc) configProvider {
    return &promptConfigProvider{label: label, hidden: false, defaultStringValue: defaultValue, validate: validate}
}

func interactiveIntValue(label string, defaultValue *int64) configProvider {
    return &promptConfigProvider{label: label, defaultIntValue: defaultValue}
}

func interactiveBoolValue(label string, defaultValue *bool) configProvider {
    return &promptConfigProvider{label: label, defaultBoolValue: defaultValue}
}

func interactivePasswordValue(label string) configProvider {
    return &promptConfigProvider{label: label, hidden: true}
}

//
// Menu Config provider returns a menu selection
//

type menuConfigProvider struct {
    label        string
    items        map[string]*string
    defaultValue *string
}

func (p *menuConfigProvider) location() string {
    return "user selection"
}

func (p *menuConfigProvider) stringValue() (*string, string) {
    res, err := interactiveMenuSelector(p.label, p.items, p.defaultValue)
    if err != nil {
        return nil, ""
    }

    return res, p.location()
}

func (p *menuConfigProvider) intValue() (*int64, string) {
    log.Fatal("Not implemented")
    return nil, ""
}

func (p *menuConfigProvider) boolValue() (*bool, string) {
    log.Fatal("Not implemented")
    return nil, ""
}

func interactiveMenu(label string, items map[string]*string, defaultValue *string) configProvider {
    return &menuConfigProvider{label, items, defaultValue}
}

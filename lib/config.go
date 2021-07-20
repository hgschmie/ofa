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

type configField interface {
    stringValue() (*string, string)
    intValue() (*int64, string)
    boolValue() (*bool, string)
}

type ConfigProvider func(field string) configField

// return a configured string value
func evaluateString(label string, fields ...configField) *string {
    for _, c := range fields {
        if value, source := c.stringValue(); value != nil {
            if *globalVerbose && len(label) > 0 {
                log.Infof("%s %s (%s)", padLabel(label), *value, source)
            }
            return value
        }
    }
    return nil
}

func evaluateMask(label string, fields ...configField) *string {
    for _, c := range fields {
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
func evaluateInt(label string, fields ...configField) *int64 {
    for _, c := range fields {
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
func evaluateBool(label string, fields ...configField) (*bool, string) {
    for _, c := range fields {
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
type flagConfig struct {
    flags    *pflag.FlagSet
    flagname string
    negate   bool
}

func (p *flagConfig) location() string {
    return fmt.Sprintf("flag: '%s'", p.flagname)
}

func (p *flagConfig) stringValue() (*string, string) {
    if p.flags.Changed(p.flagname) {
        return toSPError(p.flags.GetString(p.flagname)), p.location()
    }
    return nil, ""
}

func (p *flagConfig) intValue() (*int64, string) {
    if p.flags.Changed(p.flagname) {
        return toIPError(p.flags.GetInt64(p.flagname)), p.location()
    }
    return nil, ""
}

func (p *flagConfig) boolValue() (*bool, string) {
    if p.flags.Changed(p.flagname) {
        v, err := p.flags.GetBool(p.flagname)
        return toBPError(v != p.negate, err), // this is v ^ p.negate, golang style. Surprisingly annoying
            p.location()
    }
    return nil, ""
}

func newFlagConfig(flags *pflag.FlagSet, negate bool) ConfigProvider {
    return func(flagname string) configField {
        return &flagConfig{flags, flagname, negate}
    }
}

//
// Null Config always return nil for any config key
//
type nullConfig struct {
}

func (p *nullConfig) stringValue() (*string, string) {
    return nil, ""
}

func (p *nullConfig) intValue() (*int64, string) {
    return nil, ""
}

func (p *nullConfig) boolValue() (*bool, string) {
    return nil, ""
}

func newNullConfig() ConfigProvider {
    return func(field string) configField {
        return &nullConfig{}
    }
}

//
// Default Config always return a default value
//
type constantConfig struct {
    defaultString *string
    defaultBool   *bool
}

func (p *constantConfig) location() string {
    return "default value"
}

func (p *constantConfig) stringValue() (*string, string) {
    return p.defaultString, p.location()
}

func (p *constantConfig) intValue() (*int64, string) {
    log.Fatal("Not implemented")
    return nil, ""
}

func (p *constantConfig) boolValue() (*bool, string) {
    return p.defaultBool, p.location()
}

func constantStringValue(defaultString string) configField {
    return &constantConfig{defaultString: &defaultString}
}

func constantBoolValue(defaultBool bool) configField {
    return &constantConfig{defaultBool: &defaultBool}
}

//
// Prompt Config prompts for user input.
//
type promptConfig struct {
    label              string
    hidden             bool
    defaultStringValue *string
    defaultIntValue    *int64
    defaultBoolValue   *bool
    validate           promptui.ValidateFunc
}

func (p *promptConfig) location(isDefault bool) string {
    if isDefault {
        return "user input (default value auto-selected)"
    }

    return "user input"
}

func (p *promptConfig) stringValue() (*string, string) {

    value, err := textInput(p.label, p.defaultStringValue, p.hidden, p.validate)
    if err != nil || len(*value) == 0 {
        return nil, ""
    }
    return value, p.location(p.defaultStringValue == value)
}

func (p *promptConfig) intValue() (*int64, string) {
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

func (p *promptConfig) boolValue() (*bool, string) {
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

func interactiveStringValue(label string, defaultValue *string, validate promptui.ValidateFunc) configField {
    return &promptConfig{label: label, hidden: false, defaultStringValue: defaultValue, validate: validate}
}

func interactiveIntValue(label string, defaultValue *int64) configField {
    return &promptConfig{label: label, defaultIntValue: defaultValue}
}

func interactiveBoolValue(label string, defaultValue *bool) configField {
    return &promptConfig{label: label, defaultBoolValue: defaultValue}
}

func interactivePasswordValue(label string) configField {
    return &promptConfig{label: label, hidden: true}
}

//
// Menu Config provider returns a menu selection
//

type menuConfig struct {
    label        string
    items        map[string]*string
    defaultValue *string
}

func (p *menuConfig) location() string {
    return "user selection"
}

func (p *menuConfig) stringValue() (*string, string) {
    res, err := interactiveMenuSelector(p.label, p.items, p.defaultValue)
    if err != nil {
        return nil, ""
    }

    return res, p.location()
}

func (p *menuConfig) intValue() (*int64, string) {
    log.Fatal("Not implemented")
    return nil, ""
}

func (p *menuConfig) boolValue() (*bool, string) {
    log.Fatal("Not implemented")
    return nil, ""
}

func interactiveMenu(label string, items map[string]*string, defaultValue *string) configField {
    return &menuConfig{label, items, defaultValue}
}

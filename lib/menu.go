package ofa

import (
    "fmt"
    "os"
    "sort"

    "github.com/manifoldco/promptui"
    log "github.com/sirupsen/logrus"
)

func interactiveMenuSelector(label string, entries map[string]*string, defaultValue *string) (*string, error) {
    items := make([]string, 0, len(entries))

    var defaultSelect *string = nil

    for k, v := range entries {
        items = append(items, k)
        if defaultValue != nil && v != nil && *v == *defaultValue {
            defaultSelect = toSP(k)
        }
    }

    result, err := menuSelector(label, items, defaultSelect)
    if err != nil {
        return nil, err
    }

    if result == nil {
        return nil, nil
    }

    return entries[*result], nil
}

func oktaAuthMethodMenuSelector(label string, authFactors []oktaAuthFactor) (*oktaAuthFactor, error) {
    m := make(map[string]*oktaAuthFactor, len(authFactors))
    items := make([]string, len(authFactors))
    for i, v := range authFactors {
        m[v.String()] = &v
        items[i] = v.String()
    }

    result, err := menuSelector(label, items, nil)
    if err != nil {
        return nil, err
    }

    if result == nil {
        return nil, nil
    }

    return m[*result], nil
}

func awsRoleMenuSelector(label string, roles []samlAwsRole) (*samlAwsRole, error) {
    m := make(map[string]*samlAwsRole, len(roles))
    items := make([]string, len(roles))
    for i, v := range roles {
        m[v.String()] = &v
        items[i] = v.String()
    }

    result, err := menuSelector(label, items, nil)
    if err != nil {
        return nil, err
    }

    if result == nil {
        return nil, nil
    }

    return m[*result], nil
}

func menuSelector(label string, items []string, defaultValue *string) (*string, error) {

    if !*globalInteractive {
        return nil, fmt.Errorf("Selection required but not interactive")
    }

    sort.Strings(items)
    cursorPos := 0

    for i, v := range items {
        if defaultValue != nil && *defaultValue == v {
            cursorPos = i
        }
    }

    prompt := promptui.Select{
        Label:     label,
        Items:     items,
        CursorPos: cursorPos,
        HideHelp:  true,
        Stdout:    &bellSkipper{},
    }

    index, _, err := prompt.Run()

    if err != nil {
        checkForKeyboard(err)
        return nil, err
    }

    return &items[index], nil
}

func textInput(label string, defaultValue *string, hidden bool, validate promptui.ValidateFunc) (*string, error) {

    if !*globalInteractive {
        if defaultValue != nil {
            return defaultValue, nil
        }

        return nil, fmt.Errorf("Input required but not interactive")
    }

    prompt := promptui.Prompt{
        Label:    label,
        Validate: validate,
        Stdout:   &bellSkipper{},
    }

    if hidden {
        prompt.Mask = '*'
    }

    if defaultValue != nil {
        prompt.Default = *defaultValue
    }

    value, err := prompt.Run()

    if err != nil {
        checkForKeyboard(err)
        return nil, err
    }

    return &value, nil
}

func checkForKeyboard(err error) {
    if err == promptui.ErrInterrupt {
        log.Fatal("Terminated by ^C")
    } else if err == promptui.ErrEOF {
        log.Fatal("Terminated by ^D")
    }
}

// bellSkipper implements an io.WriteCloser that skips the terminal bell
// character (ASCII code 7), and writes the rest to os.Stderr. It is used to
// replace readline.Stdout, that is the package used by promptui to display the
// prompts.
//
// This is a workaround for the bell issue documented in
// https://github.com/manifoldco/promptui/issues/49.
type bellSkipper struct{}

// Write implements an io.WriterCloser over os.Stderr, but it skips the terminal
// bell character.
func (bs *bellSkipper) Write(b []byte) (int, error) {
    const charBell = 7 // c.f. readline.CharBell
    if len(b) == 1 && b[0] == charBell {
        return 0, nil
    }
    return os.Stderr.Write(b)
}

// Close implements an io.WriterCloser over os.Stderr.
func (bs *bellSkipper) Close() error {
    return os.Stderr.Close()
}

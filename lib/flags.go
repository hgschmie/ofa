package ofa

import (
    "os"

    "github.com/spf13/pflag"
)

var (
    // whether to run quiet or verbose
    globalVerbose *bool

    // whether to be interactive or not
    globalInteractive *bool

    // whether to ignore the config or not
    globalNoConfig *bool

    verboseSource     string
    interactiveSource string
    noConfigSource    string
)

func init() {
    globalVerbose = toBP(true)
    globalInteractive = toBP(true)
    globalNoConfig = toBP(false)
}

func SetGlobalFlags(flags *pflag.FlagSet) {
    // resolve the verbose flags etc.
    rootConfigProvider := defaultConfigProvider()
    flagConfigProvider := newFlagConfigProvider(flags, false)
    notFlagConfigProvider := newFlagConfigProvider(flags, true)

    // set the global without label first, so no echoing
    globalVerbose, verboseSource = evaluateBool("", flagConfigProvider(FlagVerbose),
        notFlagConfigProvider(FlagQuiet),
        rootConfigProvider(globalKeyVerbose),
        defaultBoolValue(true))

    globalNoConfig, noConfigSource = evaluateBool("",
        flagConfigProvider(FlagNoConfig),
        defaultBoolValue(false))

    globalInteractive, interactiveSource = evaluateBool("",
        flagConfigProvider(FlagInteractive),
        notFlagConfigProvider(FlagBatch),
        rootConfigProvider(globalKeyInteractive),
        defaultBoolValue(isTTY(os.Stderr))) // by default, the app prompts for things if connected to a tty
}

func DisplayGlobalFlags() {

    // here the verbose flag is set correctly.
    Information("**** Global Flags:")
    Information("%s %t (%s)", padLabel(labelIgnoreConfig), *globalNoConfig, noConfigSource)
    Information("%s %t (%s)", padLabel(labelVerbose), *globalVerbose, verboseSource)
    Information("%s %t (%s)", padLabel(labelInteractive), *globalInteractive, interactiveSource)
}

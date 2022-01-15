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
	rootConfigProvider := configStore.defaultConfigProvider()
	flagConfigProvider := newFlagConfig(flags, false)
	notFlagConfigProvider := newFlagConfig(flags, true)

	// set the global without label first, so no echoing
	globalVerbose, verboseSource = evaluateBool("", flagConfigProvider(FlagVerbose),
		notFlagConfigProvider(FlagQuiet),
		rootConfigProvider(globalKeyVerbose),
		constantBoolValue(true))

	globalNoConfig, noConfigSource = evaluateBool("",
		flagConfigProvider(FlagNoConfig),
		constantBoolValue(false))

	globalInteractive, interactiveSource = evaluateBool("",
		flagConfigProvider(FlagInteractive),
		notFlagConfigProvider(FlagBatch),
		rootConfigProvider(globalKeyInteractive),
		constantBoolValue(isTTY(os.Stderr))) // by default, the app prompts for things if connected to a tty
}

func ForceBatch() {
	globalInteractive = toBP(false)
}

func DisplayGlobalFlags() {
	// here the verbose flag is set correctly.
	Information("**** Global Flags:")
	Information("%s %t (%s)", padLabel(labelIgnoreConfig), *globalNoConfig, noConfigSource)
	Information("%s %t (%s)", padLabel(labelVerbose), *globalVerbose, verboseSource)
	Information("%s %t (%s)", padLabel(labelInteractive), *globalInteractive, interactiveSource)
}

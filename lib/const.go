package ofa

const (
	// global command line flags

	FlagInteractive = "interactive"
	FlagBatch       = "batch"
	FlagVerbose     = "verbose"
	FlagQuiet       = "quiet"
	FlagNoConfig    = "no-config"

	FlagSetInteractive = "set-interactive"
	FlagSetVerbose     = "set-verbose"

	// set value flags

	FlagSetProfile     = "set-profile"
	FlagSetProfileType = "set-profile-type"
	FlagSetRole        = "set-role"
	FlagSetSessionTime = "set-session-time"
	FlagSetUser        = "set-user"
	FlagSetURL         = "set-url"

	// value flags

	FlagPassword    = "password"
	FlagProfile     = "profile"
	FlagRole        = "role"
	FlagSessionTime = "session-time"
	FlagUser        = "user"
	FlagProfileType = "profile-type"
	FlagURL         = "url"

	FlagDescSetVerbose     = "Sets the default verbose flag."
	FlagDescSetInteractive = "Sets the default interactive flag."
	FlagDescSetProfileName = "Sets the default profile name."
	FlagDescSetURL         = "Sets the base/organization URL."

	FlagDescSetProfileType = "Sets the profile type " + allAuthTypes + "."
	FlagDescSetUser        = "Sets the username."

	FlagDescSetRole        = "Sets the AWS role to assume."
	FlagDescSetSessionTime = "Sets the AWS session time."

	FlagDescUser        = "Username to use."
	FlagDescProfileType = "Profile Type to use " + allAuthTypes + "."
	FlagDescPassword    = "Password to use."
	FlagDescRole        = "AWS role to assume."
	FlagDescSessionTime = "AWS session time to use."
	FlagDescURL         = "Base/organization URL to use."

	profilePrefix = "profile_"

	// global config keys

	globalKeyVerbose     = "verbose"
	globalKeyInteractive = "interactive"
	globalKeyProfile     = "profile"

	// profile config keys

	profileKeyProfileType = "idp_type" // not profile_type because of conflict with profile settings
	profileKeyUser        = "user"
	profileKeyURL         = "url"

	profileKeyRole        = "aws_role"
	profileKeySessionTime = "aws_session_time"

	// global labels

	labelIgnoreConfig = "Ignore Configuration"
	labelProfile      = "Profile name"
	labelProfileType  = "Profile type"
	labelInteractive  = "Interactive"
	labelVerbose      = "Verbose"

	// profile labels

	labelPassword    = "Password"
	labelRole        = "AWS role"
	labelSessionTime = "AWS session duration"
	labelUser        = "Username"
	labelURL         = "Base/organization URL"
)

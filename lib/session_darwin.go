//go:build darwin
// +build darwin

package ofa

func promptSessionPassword(session *LoginSession) {
	keychainConfigProvider := newKeychainEntry(session.URL)

	session.Password = evaluateMask(labelPassword,
		session.flagConfig(FlagPassword),        // --password flag
		keychainConfigProvider(session.User),    // keychain stored password
		interactivePasswordValue(labelPassword)) // interactive prompt
}

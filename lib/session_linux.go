// +build linux

package ofa

// keychain package should compile on linux but does not. Do not support
// secrets keychain on linux for now.
//
func promptSessionPassword(session *LoginSession)  {
	session.Password = evaluateMask(labelPassword,
        session.flagConfig(FlagPassword),     // --password flag
        interactivePasswordValue(labelPassword)) // interactive prompt
}

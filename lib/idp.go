package ofa

const (
    oktaName     = "okta"
    auth0Name    = "auth0"
    oneloginName = "onelogin"

    allAuthTypes = "(" + oktaName + ", " + auth0Name + ", " + oneloginName + ")"

    // state machine constants

    StateLogin        = "LOGIN"
    StateSuccess      = "SUCCESS"
    StateMfaRequired  = "MFA_REQUIRED"
    StateMfaChallenge = "MFA_CHALLENGE"
    StateMfaPrompt    = "MFA_PROMPT"
    StateMfaVerify    = "MFA_VERIFY"
    StateSamlAssert   = "SAML_ASSERT"
)

var (
    IdentityProviders = map[string]identityProvider{
        oktaName:     &OktaIdentityProvider{},
        auth0Name:    &Auth0IdentityProvider{},
        oneloginName: &OneloginIdentityProvider{},
    }

    idpProfiles  map[string]IdpProfile
    availableIdp map[string]*string
)

func init() {
    idpProfiles = make(map[string]IdpProfile)
    availableIdp = make(map[string]*string)

    for name, v := range IdentityProviders {
        idpProfiles[name] = v.providerProfile()
        availableIdp[v.name()] = toSP(name)
    }
    availableIdp["<unset>"] = nil
}

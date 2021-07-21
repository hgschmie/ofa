package ofa

const (
    oktaName  = "okta"
    auth0Name = "auth0"

    allAuthTypes = "(" + oktaName + ", " + auth0Name + ")"
)

var (
    IdentityProviders = map[string]identityProvider{
        oktaName:  &OktaIdentityProvider{},
        auth0Name: &Auth0IdentityProvider{},
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
}

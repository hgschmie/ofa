package ofa

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/http/cookiejar"
    "strings"
    "time"

    "github.com/manifoldco/promptui"
    "github.com/pelletier/go-toml"
    log "github.com/sirupsen/logrus"
    "github.com/spf13/pflag"
    "github.com/spf13/viper"
)

const (
    // set value flags

    flagSetAuth0AuthMethod   = "set-auth0-auth-method"
    flagSetAuth0ClientId     = "set-auth0-client-id"
    flagSetAuth0ClientSecret = "set-auth0-client-secret"

    // value flags

    flagAuth0AuthMethod   = "auth0-auth-method"
    flagAuth0ClientId     = "auth0-client-id"
    flagAuth0ClientSecret = "auth0-client-secret"

    flagDescSetAuth0AuthMethod   = "Sets the Auth0 Auth method."
    flagDescSetAuth0ClientId     = "Sets the Auth0 Client Id."
    flagDescSetAuth0ClientSecret = "Sets the Auth0 Client Secret."

    // profile config keys

    profileKeyAuth0AuthMethod   = "auth0_auth_method"
    profileKeyAuth0ClientId     = "auth0_client_id"
    profileKeyAuth0ClientSecret = "auth0_client_secret"

    // profile labels

    labelAuth0AuthMethod   = "Auth0 auth method"
    labelAuth0ClientId     = "Auth0 Application Client Id"
    labelAuth0ClientSecret = "Auth0 Application Client Secret"
)

var (
    auth0AuthMethods = map[string]*string{
        "Push Notification":                  toSP("push"),
        "Text Message":                       toSP("sms"),
        "Voice Message":                      toSP("voice"),
        "TOTP (Google Authenticator, Authy)": toSP("token"),
        "Recovery Token":                     toSP("recovery-token"),
        "<unset>":                            nil,
    }

    auth0Jar    *cookiejar.Jar
    auth0Client *http.Client

    auth0Types = map[string]*auth0FactorInfo{
        "push": {
            FactorName: "push",
            NextState:  StateMfaChallenge,
            GrantType:  "http://auth0.com/oauth/grant-type/mfa-oob",
        },
        "sms": {
            "sms",
            StateMfaChallenge,
            "http://auth0.com/oauth/grant-type/mfa-oob",
            func() (string, error) {
                prompt := promptui.Prompt{
                    Label: "Enter SMS code",
                }
                result, err := prompt.Run()

                return result, err
            },
        },
        "voice": {
            "voice",
            StateMfaChallenge,
            "http://auth0.com/oauth/grant-type/mfa-oob",
            func() (string, error) {
                prompt := promptui.Prompt{
                    Label: "Enter Voice message code",
                }
                result, err := prompt.Run()

                return result, err
            },
        },
        "totp": {
            "token",
            StateMfaPrompt,
            "http://auth0.com/oauth/grant-type/mfa-otp",
            func() (string, error) {
                prompt := promptui.Prompt{
                    Label: "Enter OTP Challenge",
                }
                result, err := prompt.Run()

                return result, err
            },
        },
        "recovery-code": {
            "recovery-code",
            StateMfaPrompt,
            "http://auth0.com/oauth/grant-type/mfa-recovery-code",
            func() (string, error) {
                prompt := promptui.Prompt{
                    Label: "Enter Recovery Code",
                }
                result, err := prompt.Run()

                return result, err
            },
        },
    }
)

func init() {
    auth0Jar, _ = cookiejar.New(
        &cookiejar.Options{})

    auth0Client = &http.Client{
        Jar: auth0Jar,
    }
}

/*
 * auth0 logic
 */

type Auth0IdentityProvider struct {
    AuthMethod   *string `validate:"omitempty,oneof=push sms voice totp recovery-code"`
    ClientId     *string `validate:"required"`
    ClientSecret *string `validate:"required"`

    config       *LoginSession
    state        string
    mfaToken     *string
    mfaFactor    *auth0MfaResponse
    factorInfo   *auth0FactorInfo
    mfaChallenge *auth0ChallengeResponse
    authToken    *string
    response     *string
}

func (p *Auth0IdentityProvider) name() string {
    return "Auth0 (no not use)"
}

func (p *Auth0IdentityProvider) providerProfile() IdpProfile {
    return &Auth0ProfileSettings{}
}

func (p *Auth0IdentityProvider) DefaultFlags(flags *pflag.FlagSet) {
    flags.String(flagSetAuth0AuthMethod, "", flagDescSetAuth0AuthMethod)
    flags.String(flagSetAuth0ClientId, "", flagDescSetAuth0ClientId)
    flags.String(flagSetAuth0ClientSecret, "", flagDescSetAuth0ClientSecret)
}

func (p *Auth0IdentityProvider) LoginFlags(flags *pflag.FlagSet) {
}

func (p *Auth0IdentityProvider) ProfileFlags(flags *pflag.FlagSet) {
    flags.String(flagSetAuth0AuthMethod, "", flagDescSetAuth0AuthMethod)
    flags.String(flagSetAuth0ClientId, "", flagDescSetAuth0ClientId)
    flags.String(flagSetAuth0ClientSecret, "", flagDescSetAuth0ClientSecret)
}

type Auth0ProfileSettings struct {
    url          *string `validate:"omitempty,url"`
    authMethod   *string `validate:"omitempty,oneof=push sms voice totp recovery-code"`
    clientId     *string `validate:"omitempty,url"`
    clientSecret *string `validate:"omitempty,url"`
}

type auth0AuthRequest struct {
    Username     string  `json:"username"`
    Password     string  `json:"password"`
    GrantType    string  `json:"grant_type"`
    ClientId     string  `json:"client_id"`
    ClientSecret string  `json:"client_secret"`
    Audience     string  `json:"audience"`
    Scope        *string `json:"scope,omitempty"`
}

type auth0ChallengeRequest struct {
    MfaToken        string `json:"mfa_token"`
    ChallengeType   string `json:"challenge_type"`
    AuthenticatorId string `json:"authenticator_id"`
    ClientId        string `json:"client_id"`
    ClientSecret    string `json:"client_secret"`
}

type auth0ChallengeResponse struct {
    ChallengeType *string `json:"challenge_type"`
    OOBCode       string  `json:"oob_code"`
    BindingMethod *string `json:"binding_method,omitempty"`
}

type auth0TokenRequest struct {
    GrantType    string  `json:"grant_type"`
    ClientId     string  `json:"client_id"`
    ClientSecret string  `json:"client_secret"`
    MfaToken     string  `json:"mfa_token"`
    OOBCode      *string `json:"oob_code,omitempty"`
    Otp          *string `json:"otp,omitempty"`
    BindingCode  *string `json:"binding_code,omitempty"`
    RecoveryCode *string `json:"recovery_code,omitempty"`
}

type auth0FactorInfo struct {
    FactorName string
    NextState  string
    GrantType  string
    Prompt     func() (string, error)
}

type auth0Response struct {
    AccessToken *string `json:"access_token,omitempty"`
    Scope       *string `json:"scope,omitempty"`
    ExpiresIn   int     `json:"expires_in,omitempty"`
    TokenType   *string `json:"token_type,omitempty"`
}

type Auth0Error interface {
    Error() string
    Code() int
    Response() auth0ErrorResponse
}

func (p *Auth0IdentityProvider) Configure(config *LoginSession) error {
    p.config = config

    p.AuthMethod = evaluateString(labelAuth0AuthMethod,
        config.flagConfig(flagAuth0AuthMethod),
        config.profileConfig(profileKeyAuth0AuthMethod),
        config.rootConfig(profileKeyAuth0AuthMethod),
        interactiveMenu(labelAuth0AuthMethod, auth0AuthMethods, nil))

    p.ClientId = evaluateString(labelAuth0ClientId,
        config.flagConfig(flagAuth0ClientId),
        config.profileConfig(profileKeyAuth0ClientId),
        config.rootConfig(profileKeyAuth0ClientId),
        interactiveStringValue(labelAuth0ClientId, nil, nil))

    p.ClientSecret = evaluateMask(labelAuth0ClientSecret,
        config.flagConfig(flagAuth0ClientSecret),
        config.profileConfig(profileKeyAuth0ClientSecret),
        config.rootConfig(profileKeyAuth0ClientSecret),
        interactivePasswordValue(labelAuth0ClientSecret))

    return validate.Struct(p)
}

func (p *Auth0IdentityProvider) Validate() error {
    return nil
}

//
// Login logs into Auth0 using username and password
//
func (p *Auth0IdentityProvider) Login() (*string, error) {
    Information("**** Logging into Auth0")

    p.state = StateLogin

    var err error = nil

    for {
        if err != nil {
            return nil, err
        }
        switch p.state {
        case StateLogin:
            err = p.auth0StateLogin()
        case StateSuccess:
            return p.authToken, nil
        case StateMfaRequired:
            err = p.auth0StateMFAInitiate()
        case StateMfaPrompt:
            err = p.auth0StateMFAPrompt()
        case StateMfaChallenge:
            err = p.auth0StateMFAChallenge()
        case StateMfaVerify:
            err = p.auth0StateMFAVerify()
        default:
            return nil, fmt.Errorf("Auth0 Session status: %s", p.state)
        }
    }
}

func (p *Auth0IdentityProvider) InitiateSession(sessionToken string) (samlResponse *string, err error) {
    Information("**** Fetching Auth0 SAML response")

    // this code does nto work. It is a placeholder until I figure out
    // how to do this with auth0 (see https://community.auth0.com/t/exchange-a-bearer-token-for-a-saml-assertion/59354)

    var samlUrl string = "/samlp/" + *p.ClientId + "?connection=Username-Password-Authentication"
    userinfoURL, err := p.config.URL.Parse(samlUrl)
    if err != nil {
        return nil, err
    }

    response, err := auth0Get(userinfoURL.String(), &sessionToken)
    if err != nil {
        return nil, err
    }

    r := make(map[string]interface{}, 0)
    err = json.Unmarshal(response, &r)
    if err != nil {
        return nil, err
    }
    log.Panicf("Result: %v", r)

    return nil, nil
}

func (p *Auth0IdentityProvider) auth0StateLogin() error {

    audience, err := p.config.URL.Parse("/api/v2/")
    if err != nil {
        return err
    }

    reqBody, err := json.Marshal(auth0AuthRequest{
        Username:     p.config.User,
        Password:     *p.config.Password,
        GrantType:    "password",
        ClientId:     *p.ClientId,
        ClientSecret: *p.ClientSecret,
        Audience:     audience.String(),
        Scope:        toSP("openid"),
    })

    if err != nil {
        return err
    }

    reqUrl, err := p.config.URL.Parse("/oauth/token")
    if err != nil {
        return err
    }

    r, err := auth0Post(reqUrl.String(), reqBody)
    if err != nil {
        var e Auth0Error
        if !errors.As(err, &e) {
            return err
        }
        if e.Code() == 403 && e.Response().ErrorField == "mfa_required" {
            p.mfaToken = e.Response().MfaToken
            p.state = StateMfaRequired
            return nil
        }

        return err
    }

    auth0Response := new(auth0Response)
    if err = json.Unmarshal(r, auth0Response); err != nil {
        return err
    }

    // got a token in the first shot. Declare success
    p.authToken = auth0Response.AccessToken
    p.state = StateSuccess
    return nil
}

type auth0MfaResponse struct {
    Id         string  `json:"id"`
    Type       string  `json:"authenticator_type"`
    Name       *string `json:"name,omitempty"`
    Active     bool    `json:"active"`
    OOBChannel *string `json:"oob_channel,omitempty"`
}

func (f auth0MfaResponse) mfaType() (*string, error) {
    ids := strings.Split(f.Id, "|")
    if len(ids) != 2 {
        return nil, fmt.Errorf("MFA id %s is malformed!", f.Id)
    }
    return toSP(strings.ToLower(ids[0])), nil
}

func (f auth0MfaResponse) String() string {
    mfaType, err := f.mfaType()
    if err != nil {
        log.Panicf("Can not parse MFA type: %s", f.Id)
    }

    switch *mfaType {
    case "push":
        return fmt.Sprintf("Push notification/TOTP on %s", *f.Name)
    case "sms":
        return fmt.Sprintf("Text message to %s", *f.Name)
    case "voice":
        return fmt.Sprintf("Voice call to %s", *f.Name)
    case "totp":
        return fmt.Sprintf("TOTP (Google Authenticator, Authy etc.)")
    case "recovery-code":
        return fmt.Sprintf("Recovery code")
    default:
        log.Panicf("Unknown authentication type: %s", f.Id)
        return ""

    }
}

func (p *Auth0IdentityProvider) auth0StateMFAInitiate() error {
    Information("**** Initiating MFA Challenge")

    mfaFactorURL, err := p.config.URL.Parse("/mfa/authenticators")
    if err != nil {
        return err
    }

    response, err := auth0Get(mfaFactorURL.String(), p.mfaToken)
    if err != nil {
        return err
    }

    mfaResponse := make([]auth0MfaResponse, 0)

    if err = json.Unmarshal(response, &mfaResponse); err != nil {
        return err
    }

    candidates := make([]auth0MfaResponse, 0)

    for _, factor := range mfaResponse {
        if factor.Active {
            mfaType, err := factor.mfaType()
            if err != nil {
                return err
            }

            if _, ok := auth0Types[*mfaType]; ok {
                if p.AuthMethod == nil || strings.ToLower(*p.AuthMethod) == *mfaType {
                    candidates = append(candidates, factor)
                }
            } else {
                log.Errorf("Unknown Factor type '%s' encountered, ignoring!", *mfaType)
            }
        }
    }

    switch len(candidates) {
    case 0:
        return fmt.Errorf("authentication using MFA requested, but no available factor found")
    case 1:
        p.mfaFactor = &candidates[0]
    default:
        result, err := auth0AuthMethodMenuSelector("Select MFA Method", candidates)
        if err != nil {
            return err
        }
        p.mfaFactor = result
    }

    mfaType, err := p.mfaFactor.mfaType()
    if err != nil {
        return err
    }

    var ok bool
    if p.factorInfo, ok = auth0Types[*mfaType]; !ok {
        return fmt.Errorf("Unknown Factor type '%s' encountered, ignoring!", *mfaType)
    }

    // auth method decides where to go next.
    p.state = p.factorInfo.NextState

    return nil
}

// prompt the user for input. Can be OTP challenge, recovery code or SMS/Voice response
func (p *Auth0IdentityProvider) auth0StateMFAPrompt() error {
    if p.factorInfo.Prompt == nil {
        return fmt.Errorf("Received Auth0 Challenge but %s does not support challenging!", p.mfaFactor.Id)
    }

    result, err := p.factorInfo.Prompt()
    if err != nil {
        return err
    }

    p.response = &result
    p.state = StateMfaVerify
    return nil
}

// issue a challenge to the user. This triggers sending a push / sms / voice call
func (p *Auth0IdentityProvider) auth0StateMFAChallenge() error {

    reqBody, err := json.Marshal(auth0ChallengeRequest{
        MfaToken:        *p.mfaToken,
        ChallengeType:   p.mfaFactor.Type,
        AuthenticatorId: p.mfaFactor.Id,
        ClientId:        *p.ClientId,
        ClientSecret:    *p.ClientSecret,
    })

    if err != nil {
        return err
    }

    reqUrl, err := p.config.URL.Parse("/mfa/challenge")
    if err != nil {
        return err
    }

    r, err := auth0Post(reqUrl.String(), reqBody)
    if err != nil {
        return err
    }

    response := new(auth0ChallengeResponse)
    if err = json.Unmarshal(r, response); err != nil {
        return err
    }

    p.mfaChallenge = response

    if p.factorInfo.Prompt != nil {
        p.state = StateMfaPrompt // SMS and voice need input of a passcode
    } else {
        p.state = StateMfaVerify
    }

    return nil
}

//
// - from challenge if push was used
// - from prompt if otp was used
//
func (p *Auth0IdentityProvider) auth0StateMFAVerify() error {

    req := auth0TokenRequest{
        GrantType:    p.factorInfo.GrantType,
        MfaToken:     *p.mfaToken,
        ClientId:     *p.ClientId,
        ClientSecret: *p.ClientSecret,
    }

    switch p.mfaFactor.Type {
    case "oob":
        req.OOBCode = &p.mfaChallenge.OOBCode
        req.BindingCode = p.response
    case "otp":
        req.Otp = p.response
    case "recovery-code":
        req.RecoveryCode = p.response
    }

    reqBody, err := json.Marshal(req)
    if err != nil {
        return err
    }

    authnURL, err := p.config.URL.Parse("/oauth/token")

    if err != nil {
        return err
    }

    for {
        r, err := auth0Post(authnURL.String(), reqBody)

        if err != nil {
            var e Auth0Error
            if !errors.As(err, &e) {
                return err
            }

            // user has not yet responsed. Retry with reasonable delays
            if e.Code() == 400 {
                switch e.Response().ErrorField {
                case "authorization_pending":
                    time.Sleep(5 * time.Second) // auth0 expects 5 seconds
                    continue
                case "slow_down":
                    time.Sleep(10 * time.Second) // should never happen
                    continue
                }
            }

            return err
        }

        response := new(auth0Response)
        if err = json.Unmarshal(r, response); err != nil {
            return err
        }

        p.authToken = response.AccessToken
        p.state = StateSuccess
        return nil
    }
}

func auth0AuthMethodMenuSelector(label string, authFactors []auth0MfaResponse) (*auth0MfaResponse, error) {
    m := make(map[string]*auth0MfaResponse, len(authFactors))
    items := make([]string, len(authFactors))
    for i, v := range authFactors {
        m[v.String()] = &authFactors[i]
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

//
// auth0ErrorResponse contains the Auth0 body of a non-200 response.
//
type auth0ErrorResponse struct {
    ErrorField       string  `json:"error"`
    ErrorDescription string  `json:"error_description"`
    MfaToken         *string `json:"mfa_token,omitempty"`
    code             int
}

func (a *auth0ErrorResponse) Code() int {
    return a.code
}

func (a *auth0ErrorResponse) Response() auth0ErrorResponse {
    return *a
}

func (a *auth0ErrorResponse) Error() string {
    return a.ErrorDescription
}

func auth0AuthError(response *http.Response, responseBody []byte) error {
    var errorResponse auth0ErrorResponse
    if err := json.Unmarshal(responseBody, &errorResponse); err != nil {
        return fmt.Errorf("auth0 response body garbled")
    }

    errorResponse.code = response.StatusCode

    if response.StatusCode == 401 {
        return fmt.Errorf("could not log into Auth0: %s", errorResponse.ErrorDescription)
    }

    return &errorResponse
}

func auth0Post(url string, body []byte) ([]byte, error) {

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
    if err != nil {
        return nil, err
    }

    req.Header.Set("Accept", "application/json")
    req.Header.Set("Cache-Control", "no-store")
    req.Header.Set("Content-Type", "application/json")

    response, err := auth0Client.Do(req)
    if err != nil {
        return nil, err
    }

    defer response.Body.Close()

    responseBody, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return nil, err
    }

    if response.StatusCode != 200 {
        return nil, auth0AuthError(response, responseBody)
    }

    return responseBody, nil
}

func auth0Get(url string, token *string) ([]byte, error) {

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Cache-Control", "no-store")

    if token != nil {
        req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *token))
    }

    response, err := auth0Client.Do(req)
    if err != nil {
        return nil, err
    }

    defer response.Body.Close()

    responseBody, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return nil, err
    }

    if response.StatusCode != 200 {
        return nil, auth0AuthError(response, responseBody)
    }

    return responseBody, nil
}

//
// Profile settings
//

func (p *Auth0ProfileSettings) Create() IdpProfile {
    return &Auth0ProfileSettings{}
}

func (p *Auth0ProfileSettings) Validate() error {
    return validate.Struct(p)
}

func (p *Auth0ProfileSettings) Log(profileName *string) {
    logStringSetting(profilePrompt(profileName, labelAuth0AuthMethod), p.authMethod)
    logStringSetting(profilePrompt(profileName, labelAuth0ClientId), p.clientId)
}

func (p *Auth0ProfileSettings) Load(s *viper.Viper) {

    p.authMethod = getString(s, profileKeyAuth0AuthMethod)
    p.clientId = getString(s, profileKeyAuth0ClientId)
    p.clientSecret = getString(s, profileKeyAuth0ClientSecret)
}

func (p *Auth0ProfileSettings) Prompt(rootProfileName *string, flagConfigProvider ConfigProvider, identityProviders map[string]IdpProfile) error {

    var defaults *Auth0ProfileSettings

    if defaultSettings, ok := identityProviders[auth0Name]; ok {
        defaults = defaultSettings.(*Auth0ProfileSettings)
    } else {
        defaults = p.Create().(*Auth0ProfileSettings)
    }

    p.authMethod = evaluateString(labelAuth0AuthMethod,
        flagConfigProvider(flagSetAuth0AuthMethod),
        interactiveMenu(profilePrompt(rootProfileName, labelAuth0AuthMethod), auth0AuthMethods, defaults.authMethod))

    p.clientId = evaluateString(labelAuth0ClientId,
        flagConfigProvider(flagSetAuth0ClientId),
        interactiveStringValue(profilePrompt(rootProfileName, labelAuth0ClientId), defaults.clientId, nil))

    p.clientSecret = evaluateString(labelAuth0ClientSecret,
        flagConfigProvider(flagSetAuth0ClientSecret),
        interactiveStringValue(profilePrompt(rootProfileName, labelAuth0ClientSecret), defaults.clientSecret, nil))

    return nil
}

func (p *Auth0ProfileSettings) Store(tree *toml.Tree, prefix string) error {
    if err := setString(tree, prefix+profileKeyAuth0AuthMethod, p.authMethod); err != nil {
        return err
    }

    if err := setString(tree, prefix+profileKeyAuth0ClientId, p.clientId); err != nil {
        return err
    }

    if err := setString(tree, prefix+profileKeyAuth0ClientSecret, p.clientSecret); err != nil {
        return err
    }

    return nil
}

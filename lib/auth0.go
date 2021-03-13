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
    log "github.com/sirupsen/logrus"
)

var (
    jar         *cookiejar.Jar
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

const (
    StateLogin        = "LOGIN"
    StateSuccess      = "SUCCESS"
    StateMfaRequired  = "MFA_REQUIRED"
    StateMfaChallenge = "MFA_CHALLENGE"
    StateMfaPrompt    = "MFA_PROMPT"
    StateMfaVerify    = "MFA_VERIFY"
)

func init() {
    jar, _ = cookiejar.New(
        &cookiejar.Options{})

    auth0Client = &http.Client{
        Jar: jar,
    }
}

/*
 * auth0 logic
 */

type auth0Session struct {
    loginSession *LoginSession
    state        string
    mfaToken     *string
    mfaFactor    *auth0MfaResponse
    factorInfo   *auth0FactorInfo
    mfaChallenge *auth0ChallengeResponse
    authToken    *string
    response     *string
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

//
// Auth0Login logs into Auth0 using username and password
//
func Auth0Login(session *LoginSession) (*string, error) {
    Information("**** Logging into Auth0")

    auth0Session := &auth0Session{
        loginSession: session,
        state:        StateLogin,
    }

    var err error = nil

    for {
        if err != nil {
            return nil, err
        }
        switch auth0Session.state {
        case StateLogin:
            err = auth0StateLogin(auth0Session)
        case StateSuccess:
            return auth0Session.authToken, nil
        case StateMfaRequired:
            err = auth0StateMFAInitiate(auth0Session)
        case StateMfaPrompt:
            err = auth0StateMFAPrompt(auth0Session)
        case StateMfaChallenge:
            err = auth0StateMFAChallenge(auth0Session)
        case StateMfaVerify:
            err = auth0StateMFAVerify(auth0Session)
        default:
            return nil, fmt.Errorf("Auth0 Session status: %s", auth0Session.state)
        }
    }
}

func auth0StateLogin(session *auth0Session) error {

    audience, err := session.loginSession.Auth0.URL.Parse("/api/v2/")
    if err != nil {
        return err
    }

    reqBody, err := json.Marshal(auth0AuthRequest{
        Username:     session.loginSession.User,
        Password:     *session.loginSession.Password,
        GrantType:    "password",
        ClientId:     *session.loginSession.Auth0.ClientId,
        ClientSecret: *session.loginSession.Auth0.ClientSecret,
        Audience:     audience.String(),
        Scope:        toSP("openid"),
    })

    if err != nil {
        return err
    }

    reqUrl, err := session.loginSession.Auth0.URL.Parse("/oauth/token")
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
            session.mfaToken = e.Response().MfaToken
            session.state = StateMfaRequired
            return nil
        }

        return err
    }

    auth0Response := new(auth0Response)
    if err = json.Unmarshal(r, auth0Response); err != nil {
        return err
    }

    // got a token in the first shot. Declare success
    session.authToken = auth0Response.AccessToken
    session.state = StateSuccess
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

func auth0StateMFAInitiate(session *auth0Session) error {
    Information("**** Initiating MFA Challenge")

    mfaFactorURL, err := session.loginSession.Auth0.URL.Parse("/mfa/authenticators")
    if err != nil {
        return err
    }

    response, err := auth0Get(mfaFactorURL.String(), session.mfaToken)
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
                if session.loginSession.Auth0.AuthMethod == nil || strings.ToLower(*session.loginSession.Auth0.AuthMethod) == *mfaType {
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
        session.mfaFactor = &candidates[0]
    default:
        result, err := auth0AuthMethodMenuSelector("Select MFA Method", candidates)
        if err != nil {
            return err
        }
        session.mfaFactor = result
    }

    mfaType, err := session.mfaFactor.mfaType()
    if err != nil {
        return err
    }

    var ok bool
    if session.factorInfo, ok = auth0Types[*mfaType]; !ok {
        return fmt.Errorf("Unknown Factor type '%s' encountered, ignoring!", *mfaType)
    }

    // auth method decides where to go next.
    session.state = session.factorInfo.NextState

    return nil
}

// prompt the user for input. Can be OTP challenge, recovery code or SMS/Voice response
func auth0StateMFAPrompt(session *auth0Session) error {
    if session.factorInfo.Prompt == nil {
        return fmt.Errorf("Received Auth0 Challenge but %s does not support challenging!", session.mfaFactor.Id)
    }

    result, err := session.factorInfo.Prompt()
    if err != nil {
        return err
    }

    session.response = &result
    session.state = StateMfaVerify
    return nil
}

// issue a challenge to the user. This triggers sending a push / sms / voice call
func auth0StateMFAChallenge(session *auth0Session) error {

    reqBody, err := json.Marshal(auth0ChallengeRequest{
        MfaToken:        *session.mfaToken,
        ChallengeType:   session.mfaFactor.Type,
        AuthenticatorId: session.mfaFactor.Id,
        ClientId:     *session.loginSession.Auth0.ClientId,
        ClientSecret: *session.loginSession.Auth0.ClientSecret,
    })

    if err != nil {
        return err
    }

    reqUrl, err := session.loginSession.Auth0.URL.Parse("/mfa/challenge")
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

    session.mfaChallenge = response

    if session.factorInfo.Prompt != nil {
        session.state = StateMfaPrompt // SMS and voice need input of a passcode
    } else {
        session.state = StateMfaVerify
    }

    return nil
}

//
// - from challenge if push was used
// - from prompt if otp was used
//
func auth0StateMFAVerify(session *auth0Session) error {

    req := auth0TokenRequest{
        GrantType:    session.factorInfo.GrantType,
        MfaToken:     *session.mfaToken,
        ClientId:     *session.loginSession.Auth0.ClientId,
        ClientSecret: *session.loginSession.Auth0.ClientSecret,
    }

    switch session.mfaFactor.Type {
    case "oob":
        req.OOBCode = &session.mfaChallenge.OOBCode
        req.BindingCode = session.response
    case "otp":
        req.Otp = session.response
    case "recovery-code":
        req.RecoveryCode = session.response
    }

    reqBody, err := json.Marshal(req)
    if err != nil {
        return err
    }

    authnURL, err := session.loginSession.Auth0.URL.Parse("/oauth/token")

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

        session.authToken = response.AccessToken
        session.state = StateSuccess
        return nil
    }
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

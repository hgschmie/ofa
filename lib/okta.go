package ofa

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/http/cookiejar"
    "strings"
    "time"

    "github.com/antchfx/xpath"
    "github.com/manifoldco/promptui"
    log "github.com/sirupsen/logrus"
)

var (
    samlPath   *xpath.Expr
    oktaClient *http.Client

    oktaTypes = map[string]*factorInfo{
        "push": {FactorName: "push"},
        "sms": {"sms",
            func() (string, error) {
                prompt := promptui.Prompt{
                    Label: "Enter SMS code",
                }
                result, err := prompt.Run()

                return result, err
            },
        },
        "token:software:totp": {"token",
            func() (string, error) {
                prompt := promptui.Prompt{
                    Label: "Enter OTP Challenge",
                }
                result, err := prompt.Run()

                return result, err
            },
        },
    }
)

func init() {
    var err error
    // this *should* work with /text() and direct evaluation of the text node at the bottom of the tree,
    // but it does not. This *may* be related to https://github.com/antchfx/xpath/issues/52
    samlPath, err = xpath.Compile("string(//form[@id='appForm']/input[@name='SAMLResponse']/@value)")
    if err != nil {
        log.Panic("Could not compile saml path!")
    }

    // okta client needs a functioning cookie jar to deal with
    // the redirection cookies
    jar, _ := cookiejar.New(
        &cookiejar.Options{})

    oktaClient = &http.Client{
        Jar: jar,
    }
}

/*
 * Okta logic
 */

type oktaAuthRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type oktaLinkList struct {
    links []oktaLink
}

func (o *oktaLinkList) UnmarshalJSON(p []byte) error {
    var link oktaLink
    if err := json.Unmarshal(p, &link); err == nil {
        o.links = append(o.links, link)
    } else {
        var linkList []oktaLink
        if err := json.Unmarshal(p, &linkList); err != nil {
            return err
        }
        o.links = append(o.links, linkList...)
    }

    return nil
}

type oktaAuthTransaction struct {
    StateToken   string     `json:"stateToken"`
    SessionToken string     `json:"sessionToken"`
    ExpiresAt    *time.Time `json:"expiresAt"`
    Status       string     `json:"status"`
    FactorResult string     `json:"factorResult"`

    Embedded oktaEmbedded            `json:"_embedded"`
    Links    map[string]oktaLinkList `json:"_links"`
}

type oktaEmbedded struct {
    Factor []oktaAuthFactor `json:"factors"`
}

//
// OktaAuthFactor represents a 2fa method to verify a login
//
type oktaAuthFactor struct {
    ID         string              `json:"id"`
    FactorType string              `json:"factorType"`
    Provider   string              `json:"provider"`
    Profile    oktaFactorProfile   `json:"profile"`
    Links      map[string]oktaLink `json:"_links"`
}

type oktaAuthVerify struct {
    StateToken string  `json:"stateToken"`
    PassCode   *string `json:"passCode,omitempty"`
}

func (f oktaAuthFactor) String() string {
    switch f.FactorType {
    case "push":
        return fmt.Sprintf("Push notification to %s (%s)", f.Profile.CredentialID, f.Profile.Name)
    case "sms":
        return fmt.Sprintf("Text message to %s", f.Profile.PhoneNumber)
    case "token:software:totp":
        return fmt.Sprintf("2fa Authenticator for %s", f.Profile.CredentialID)
    default:
        return fmt.Sprintf("Unknown authentication type %s", f.FactorType)
    }
}

type oktaFactorProfile struct {
    CredentialID string `json:"credentialId"`
    PhoneNumber  string `json:"phoneNumber"`
    DeviceType   string `json:"deviceType"`
    Name         string `json:"name"`
    Platform     string `json:"platform"`
    Version      string `json:"version"`
}

type oktaLink struct {
    Name  string                  `json:"name"`
    Href  string                  `json:"href"`
    Hints map[string]oktaLinkHint `json:"hints"`
}

type oktaLinkHint []string

//
// OktaErrorResponse contains the Okta body of a non-200 response.
//
type oktaErrorResponse struct {
    ErrorCode    string        `json:"errorCode"`
    ErrorSummary string        `json:"errorSummary"`
    ErrorLink    string        `json:"errorLink"`
    ErrorID      string        `json:"errorId"`
    ErrorCauses  []interface{} `json:"errorCauses"`
}

func (oar oktaAuthTransaction) String() string {
    return fmt.Sprintf("ExpiresAt: %s, StateToken: %s, Status: %s", oar.ExpiresAt, oar.StateToken, oar.Status)
}

type factorInfo struct {
    FactorName string
    Prompt     func() (string, error)
}

type oktaSession struct {
    loginSession *LoginSession
    mfaFactor    *oktaAuthFactor
    factorInfo   *factorInfo
}

//
// OktaLogin logs into Okta using username and password
//
func OktaLogin(session *LoginSession) (*string, error) {

    Information("**** Logging into Okta")

    oktaSession := &oktaSession{loginSession: session}

    postJSON, err := json.Marshal(oktaAuthRequest{oktaSession.loginSession.User, *oktaSession.loginSession.Password})
    if err != nil {
        return nil, err
    }

    authnURL, err := oktaSession.loginSession.Okta.URL.Parse("/api/v1/authn")
    if err != nil {
        return nil, err
    }

    response, err := oktaPost(authnURL.String(), postJSON)
    if err != nil {
        return nil, err
    }

    authTransaction := new(oktaAuthTransaction)
    err = json.Unmarshal(response, authTransaction)

    for {
        if err != nil {
            return nil, err
        }

        switch authTransaction.Status {
        case "MFA_REQUIRED":
            authTransaction, err = mfaInitiate(oktaSession, authTransaction)
        case "MFA_CHALLENGE":
            authTransaction, err = mfaChallenge(oktaSession, authTransaction)
        case "SUCCESS":
            Information("**** Okta login successful")
            return &authTransaction.SessionToken, nil
        default:
            return nil, fmt.Errorf("Okta Session status: %s", authTransaction.SessionToken)
        }
    }
}

func oktaAuthError(response *http.Response, responseBody []byte) error {
    var errorResponse oktaErrorResponse
    if err := json.Unmarshal(responseBody, &errorResponse); err != nil {
        return fmt.Errorf("okta response body garbled")
    }

    if response.StatusCode == 401 {
        return fmt.Errorf("could not log into Okta: %s", errorResponse.ErrorSummary)
    }

    return fmt.Errorf("Okta Error (%d) - %s", response.StatusCode, errorResponse.ErrorSummary)
}

func mfaInitiate(oktaSession *oktaSession, authTransaction *oktaAuthTransaction) (*oktaAuthTransaction, error) {
    Information("**** Initiating MFA Challenge")

    candidates := make([]oktaAuthFactor, 0)

    for _, factor := range authTransaction.Embedded.Factor {
        if oktaFactor, ok := oktaTypes[strings.ToLower(factor.FactorType)]; ok {
            if oktaSession.loginSession.Okta.AuthMethod == nil || strings.ToLower(*oktaSession.loginSession.Okta.AuthMethod) == oktaFactor.FactorName {
                candidates = append(candidates, factor)
            }
        } else {
            log.Errorf("Unknown Factor type '%s' encountered, ignoring!", factor.FactorType)
        }
    }

    switch len(candidates) {
    case 0:
        return nil, fmt.Errorf("authentication using MFA requested, but no available factor found")
    case 1:
        oktaSession.mfaFactor = &candidates[0]
    default:
        result, err := oktaAuthMethodMenuSelector("Select MFA Method", candidates)
        if err != nil {
            return nil, err
        }
        oktaSession.mfaFactor = result
    }

    oktaSession.factorInfo = oktaTypes[strings.ToLower(oktaSession.mfaFactor.FactorType)]

    postJSON, err := json.Marshal(oktaAuthVerify{StateToken: authTransaction.StateToken})
    if err != nil {
        return nil, err
    }

    response, err := oktaPost(oktaSession.mfaFactor.Links["verify"].Href, postJSON)
    if err != nil {
        return nil, err
    }

    err = json.Unmarshal(response, authTransaction)
    if err != nil {
        return nil, err
    }

    return authTransaction, nil
}

func mfaChallenge(oktaSession *oktaSession, authTransaction *oktaAuthTransaction) (*oktaAuthTransaction, error) {
    challengeResponse := oktaAuthVerify{StateToken: authTransaction.StateToken}

    // based on the result of the *previous* interaction with the API, choose an action. If the previous
    // interaction resulted e.g. in CHALLENGE, prompt the user for the necessary factor.
    switch authTransaction.FactorResult {
    case "CHALLENGE":
        if oktaSession.factorInfo.Prompt == nil {
            return nil, fmt.Errorf("Received Okta Challenge but %s does not support challenging!", oktaSession.mfaFactor.FactorType)
        }

        result, err := oktaSession.factorInfo.Prompt()
        if err != nil {
            return nil, err
        }

        challengeResponse.PassCode = &result
    case "WAITING":
        time.Sleep(1 * time.Second)
    case "CANCELLED":
    case "REJECTED":
        return nil, fmt.Errorf("Aborted by user")
    default:
        return nil, fmt.Errorf("Factor challenge returned %s, aborting!", authTransaction.FactorResult)
    }

    postJSON, err := json.Marshal(challengeResponse)
    if err != nil {
        return nil, err
    }

    response, err := oktaPost(authTransaction.Links["next"].links[0].Href, postJSON)
    if err != nil {
        return nil, err
    }

    err = json.Unmarshal(response, authTransaction)
    if err != nil {
        return nil, err
    }

    // return the result of this interaction to the state machine
    return authTransaction, nil
}

func oktaPost(url string, body []byte) ([]byte, error) {

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
    if err != nil {
        return nil, err
    }

    req.Header.Set("Accept", "application/json")
    req.Header.Set("Cache-Control", "no-store")
    req.Header.Set("Content-Type", "application/json")

    response, err := oktaClient.Do(req)
    if err != nil {
        return nil, err
    }

    defer response.Body.Close()

    responseBody, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return nil, err
    }

    if response.StatusCode != 200 {
        return nil, oktaAuthError(response, responseBody)
    }

    return responseBody, nil
}

func oktaGet(url string) ([]byte, error) {

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Cache-Control", "no-store")

    response, err := oktaClient.Do(req)
    if err != nil {
        return nil, err
    }

    defer response.Body.Close()

    responseBody, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return nil, err
    }

    if response.StatusCode != 200 {
        return nil, oktaAuthError(response, responseBody)
    }

    return responseBody, nil
}

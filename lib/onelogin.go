package ofa

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "strconv"
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

    oneloginDefaultApi = "https://api.us.onelogin.com/"

    flagSetOneloginAuthMethod   = "set-onelogin-auth-method"
    flagSetOneloginClientId     = "set-onelogin-client-id"
    flagSetOneloginClientSecret = "set-onelogin-client-secret"
    flagSetOneloginAppId        = "set-onelogin-app-id"
    flagSetOneloginApiUrl       = "set-onelogin-api-url"

    // value flags

    flagOneloginAuthMethod   = "onelogin-auth-method"
    flagOneloginClientId     = "onelogin-client-id"
    flagOneloginClientSecret = "onelogin-client-secret"
    flagOneloginAppId        = "onelogin-app-id"
    flagOneloginApiUrl       = "onelogin-api-url"

    flagDescSetOneloginAuthMethod   = "Sets the OneLogin Auth method."
    flagDescSetOneloginClientId     = "Sets the OneLogin Client Id."
    flagDescSetOneloginClientSecret = "Sets the OneLogin Client Secret."
    flagDescSetOneloginAppId        = "Sets the OneLogin Application Id."
    flagDescSetOneloginApiUrl       = "Sets the OneLogin API Url."

    flagDescOneloginAuthMethod   = "OneLogin Auth method to use."
    flagDescOneloginClientId     = "OneLogin Client Id to use."
    flagDescOneloginClientSecret = "OneLogin Client Secret to use."
    flagDescOneloginAppId        = "OneLogin Application Id to use."
    flagDescOneloginApiUrl       = "OneLogin API Url to use."

    // profile config keys

    profileKeyOneloginAuthMethod   = "onelogin_auth_method"
    profileKeyOneloginClientId     = "onelogin_client_id"
    profileKeyOneloginClientSecret = "onelogin_client_secret"
    profileKeyOneloginAppId        = "onelogin_app_id"
    profileKeyOneloginApiUrl       = "onelogin_api_url"

    // profile labels

    labelOneloginAuthMethod   = "OneLogin auth method"
    labelOneloginClientId     = "OneLogin Application Client Id"
    labelOneloginClientSecret = "OneLogin Application Client Secret"
    labelOneloginAppId        = "OneLogin Application Id"
    labelOneloginApiUrl       = "OneLogin API Url"
)

type oneloginDeviceInfo struct {
    Name        string
    Prompt      string
    FactorName  string
    InitState   string
    VerifyState string
    PromptFunc  func() (string, error)
}

var (
    oneloginJar    *cookiejar.Jar
    oneloginClient *http.Client

    oneloginDeviceTypes = []*oneloginDeviceInfo{
        {
            Name:        "OneLogin Protect",
            Prompt:      "Push notification",
            FactorName:  "push",
            InitState:   StateMfaChallenge,
            VerifyState: StateMfaVerify,
        },
        {
            Name:        "OneLogin SMS",
            Prompt:      "Text Message",
            FactorName:  "sms",
            InitState:   StateMfaChallenge,
            VerifyState: StateMfaPrompt,
            PromptFunc: func() (string, error) {
                prompt := promptui.Prompt{
                    Label: "Enter SMS code",
                }
                result, err := prompt.Run()

                return result, err
            },
        },
        {
            Name:        "OneLogin Email",
            Prompt:      "Email",
            FactorName:  "email",
            InitState:   StateMfaChallenge,
            VerifyState: StateMfaPrompt,
            PromptFunc: func() (string, error) {
                prompt := promptui.Prompt{
                    Label: "Enter Email code",
                }
                result, err := prompt.Run()

                return result, err
            },
        },
        {
            Name:        "Google Authenticator",
            Prompt:      "TOTP (Google Authenticator, Authy)",
            FactorName:  "totp",
            InitState:   StateMfaPrompt,
            VerifyState: StateMfaVerify,
            PromptFunc: func() (string, error) {
                prompt := promptui.Prompt{
                    Label: "Enter OTP token",
                }
                result, err := prompt.Run()

                return result, err
            },
        },
        {
            FactorName: "",
            Prompt:     "<unset>",
        },
    }

    oneloginAuthMethods = make(map[string]*string, 0)
    oneloginAuthInfo    = make(map[string]*oneloginDeviceInfo, 0)
)

func init() {
    oneloginJar, _ = cookiejar.New(
        &cookiejar.Options{})

    oneloginClient = &http.Client{
        Jar: oneloginJar,
    }

    for _, deviceType := range oneloginDeviceTypes {
        if len(deviceType.FactorName) > 0 {
            oneloginAuthMethods[deviceType.Prompt] = &deviceType.FactorName
            oneloginAuthInfo[strings.ToLower(deviceType.Name)] = deviceType
        } else {
            oneloginAuthMethods[deviceType.Prompt] = nil
        }
    }

}

/*
 * Onelogin logic
 */

type OneloginIdentityProvider struct {
    AuthMethod   *string  `validate:"omitempty,oneof=push totp sms email"`
    ClientId     *string  `validate:"required"`
    ClientSecret *string  `validate:"required"`
    AppId        *string  `validate:"required"`
    ApiUrl       *url.URL `validate:"required,url"`

    config    *LoginSession
    state     string
    samlData  *string
    token     *string
    tokenType *string

    stateToken  *string
    callbackUrl *url.URL
    devices     *[]oneloginDevice

    mfaDevice     *oneloginDevice
    mfaDeviceInfo *oneloginDeviceInfo
    otpToken      *string
}

func (p *OneloginIdentityProvider) name() string {
    return "OneLogin"
}

func (p *OneloginIdentityProvider) providerProfile() IdpProfile {
    return &OneloginProfileSettings{}
}

func (p *OneloginIdentityProvider) ConfigurationFlags(flags *pflag.FlagSet) {
    flags.String(flagSetOneloginAuthMethod, "", flagDescSetOneloginAuthMethod)
    flags.String(flagSetOneloginClientId, "", flagDescSetOneloginClientId)
    flags.String(flagSetOneloginClientSecret, "", flagDescSetOneloginClientSecret)
    flags.String(flagSetOneloginAppId, "", flagDescSetOneloginAppId)
    flags.String(flagSetOneloginApiUrl, "", flagDescSetOneloginApiUrl)
}

func (p *OneloginIdentityProvider) OverrideFlags(flags *pflag.FlagSet) {
    flags.String(flagOneloginAuthMethod, "", flagDescOneloginAuthMethod)
    flags.String(flagOneloginClientId, "", flagDescOneloginClientId)
    flags.String(flagOneloginClientSecret, "", flagDescOneloginClientSecret)
    flags.String(flagOneloginAppId, "", flagDescOneloginAppId)
    flags.String(flagOneloginApiUrl, "", flagDescOneloginApiUrl)
}

func (p *OneloginIdentityProvider) Configure(config *LoginSession) error {
    p.config = config

    p.AuthMethod = evaluateString(labelOneloginAuthMethod,
        config.flagConfig(flagOneloginAuthMethod),
        config.profileConfig(profileKeyOneloginAuthMethod),
        config.rootConfig(profileKeyOneloginAuthMethod),
        interactiveMenu(labelOneloginAuthMethod, oneloginAuthMethods, nil))

    p.ClientId = evaluateString(labelOneloginClientId,
        config.flagConfig(flagOneloginClientId),
        config.profileConfig(profileKeyOneloginClientId),
        config.rootConfig(profileKeyOneloginClientId),
        interactiveStringValue(labelOneloginClientId, nil, nil))

    p.ClientSecret = evaluateMask(labelOneloginClientSecret,
        config.flagConfig(flagOneloginClientSecret),
        config.profileConfig(profileKeyOneloginClientSecret),
        config.rootConfig(profileKeyOneloginClientSecret),
        interactivePasswordValue(labelOneloginClientSecret))

    p.AppId = evaluateString(labelOneloginAppId,
        config.flagConfig(flagOneloginAppId),
        config.profileConfig(profileKeyOneloginAppId),
        config.rootConfig(profileKeyOneloginAppId),
        interactiveStringValue(labelOneloginAppId, nil, nil))

    var err error

    if p.ApiUrl, err = getURL(evaluateString(labelOneloginApiUrl,
        config.flagConfig(flagOneloginApiUrl),
        config.profileConfig(profileKeyOneloginApiUrl),
        config.rootConfig(profileKeyOneloginApiUrl),
        interactiveStringValue(labelOneloginApiUrl, toSP(oneloginDefaultApi), validateURL))); err != nil {
        return err
    }

    return validate.Struct(p)
}

func (p *OneloginIdentityProvider) Validate() error {
    return nil
}

func (p *OneloginIdentityProvider) Login() (*string, error) {

    Information("**** Logging into Onelogin")

    p.state = StateLogin
    var err error = nil
    for {
        if err != nil {
            return nil, err
        }
        switch p.state {
        case StateSuccess:
            return p.samlData, nil
        case StateLogin:
            err = p.generateOneloginToken()
        case StateSamlAssert:
            err = p.sendSamlAssertion()
        case StateMfaRequired:
            err = p.oneloginMfaInitiate()
        case StateMfaChallenge:
            err = p.oneloginStateMfaChallenge(false)
        case StateMfaVerify:
            err = p.oneloginStateMfaChallenge(true)
        case StateMfaPrompt:
            err = p.oneloginStateMfaPrompt()

        default:
            return nil, fmt.Errorf("Onelogin Session status: %s", p.state)
        }
    }
}

type oneloginTokenRequest struct {
    ClientId     string `json:"client_id"`
    ClientSecret string `json:"client_secret"`
    GrantType    string `json:"grant_type"`
}

type oneloginTokenResponse struct {
    AccessToken *string `json:"access_token,omitempty"`
    CreatedAt   *string `json:"created_at,omitempty"`
    ExpiresIn   int     `json:"expires_in,omitempty"`
    TokenType   *string `json:"token_type,omitempty"`
    AccountId   int     `json:"account_id,omitempty"`
}

func (p *OneloginIdentityProvider) generateOneloginToken() error {
    postJson, err := json.Marshal(oneloginTokenRequest{*p.ClientId, *p.ClientSecret, "client_credentials"})
    if err != nil {
        return err
    }

    apiUrl, err := p.ApiUrl.Parse("/auth/oauth2/v2/token")
    if err != nil {
        return err
    }

    response, err := oneloginPost(apiUrl.String(), nil, postJson)
    if err != nil {
        return err
    }

    tokenResponse := new(oneloginTokenResponse)
    if err = json.Unmarshal(response, tokenResponse); err != nil {
        return err
    }

    p.token = tokenResponse.AccessToken
    p.tokenType = tokenResponse.TokenType
    p.state = StateSamlAssert

    return nil
}

type oneloginSamlAssertRequest struct {
    Username  string `json:"username_or_email"`
    Password  string `json:"password"`
    AppId     string `json:"app_id"`
    Subdomain string `json:"subdomain"`
}

type oneloginSamlAssertResponse struct {
    Data        *string           `json:"data,omitempty"`
    Message     *string           `json:"message,omitempty"`
    StateToken  *string           `json:"state_token,omitempty"`
    CallbackUrl string            `json:"callback_url,omitempty"`
    Devices     *[]oneloginDevice `json:"devices,omitempty"`
    User        *oneloginUser     `json:"user,omitempty"`
}

type oneloginUser struct {
    Username  *string `json:"username,omitempty"`
    Firstname *string `json:"firstname,omitempty"`
    Lastname  *string `json:"lastname,omitempty"`
    Email     *string `json:"email,omitempty"`
    Id        int     `json:"id,omitempty"`
}

type oneloginDevice struct {
    DeviceType *string `json:"device_type,omitempty"`
    DeviceId   int     `json:"device_id,omitempty"`
}

func (p *OneloginIdentityProvider) sendSamlAssertion() error {
    postJson, err := json.Marshal(oneloginSamlAssertRequest{Username: p.config.User,
        Password:  *p.config.Password,
        AppId:     *p.AppId,
        Subdomain: strings.Split(p.config.URL.Hostname(), ".")[0],
    })

    if err != nil {
        return err
    }

    apiUrl, err := p.ApiUrl.Parse("/api/2/saml_assertion")
    if err != nil {
        return err
    }

    response, err := oneloginPost(apiUrl.String(), p.auth(), postJson)
    if err != nil {
        return err
    }

    samlResponse := new(oneloginSamlAssertResponse)

    if err := json.Unmarshal(response, samlResponse); err != nil {
        return err
    }

    if samlResponse.Data != nil {
        // success
        p.samlData = samlResponse.Data
        p.state = StateSuccess
        return nil
    }

    // MFA required
    p.state = StateMfaRequired

    if p.callbackUrl, err = url.Parse(samlResponse.CallbackUrl); err != nil {
        return err
    }

    p.stateToken = samlResponse.StateToken
    p.devices = samlResponse.Devices

    return nil
}

func (p *OneloginIdentityProvider) oneloginMfaInitiate() error {
    Information("**** Initiating MFA Challenge")

    candidates := make([]oneloginDevice, 0)
    devices := make(map[int]*oneloginDeviceInfo, 0)

    for _, device := range *p.devices {
        if candidate, ok := oneloginAuthInfo[strings.ToLower(*device.DeviceType)]; ok {
            if p.AuthMethod == nil || strings.ToLower(*p.AuthMethod) == candidate.FactorName {
                candidates = append(candidates, device)
                devices[device.DeviceId] = candidate
            }
        } else {
            log.Debugf("Unknown Factor type '%s' encountered, ignoring!", *device.DeviceType)
        }
    }

    switch len(candidates) {
    case 0:
        return fmt.Errorf("authentication using MFA requested, but no available factor found")
    case 1:
        p.mfaDevice = &candidates[0]
    default:
        result, err := oneloginAuthMethodMenuSelector("Select MFA Method", candidates, devices)
        if err != nil {
            return err
        }
        p.mfaDevice = result
    }

    p.mfaDeviceInfo = devices[p.mfaDevice.DeviceId]

    p.state = p.mfaDeviceInfo.InitState

    return nil
}

func oneloginAuthMethodMenuSelector(label string, authFactors []oneloginDevice, devices map[int]*oneloginDeviceInfo) (*oneloginDevice, error) {
    m := make(map[string]*oneloginDevice, len(authFactors))
    items := make([]string, len(authFactors))
    for i, v := range authFactors {
        items[i] = devices[v.DeviceId].Prompt
        m[items[i]] = &authFactors[i]
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

type oneloginVerifyFactorRequest struct {
    AppId       string `json:"app_id"`
    DeviceId    string `json:"device_id"`
    StateToken  string `json:"state_token"`
    OtpToken    string `json:"otp_token"`
    DoNotNotify bool   `json:"do_not_notify"`
}

type oneloginVerifyFactorResponse struct {
    Data    *string `json:"data,omitempty"`
    Message *string `json:"message,omitempty"`
}

func (p *OneloginIdentityProvider) oneloginStateMfaChallenge(verify bool) error {

    request := oneloginVerifyFactorRequest{
        AppId:       *p.AppId,
        DeviceId:    strconv.Itoa(p.mfaDevice.DeviceId),
        StateToken:  *p.stateToken,
        DoNotNotify: verify,
    }

    if p.otpToken != nil {
        request.OtpToken = *p.otpToken
    }

    reqBody, err := json.Marshal(request)

    if err != nil {
        return err
    }

    r, err := oneloginPost(p.callbackUrl.String(), p.auth(), reqBody)
    if err != nil {
        // reprompt if necessary / resend if necessary
        if authError, ok := err.(oneloginErrorStatus); ok {
            if authError.errorCode == 401 {
                p.state = StateMfaPrompt
                p.otpToken = nil
                log.Warn("Could not authenticate!")
                return nil
            }
        }
        return err
    }

    response := new(oneloginVerifyFactorResponse)
    if err = json.Unmarshal(r, response); err != nil {
        return err
    }

    if response.Data != nil {
        // success
        p.samlData = response.Data
        p.state = StateSuccess
        return nil
    }

    // rate limit for verification calls
    if verify {
        time.Sleep(6 * time.Second) // poll once every six seconds...
    }

    p.state = p.mfaDeviceInfo.VerifyState

    return nil
}

func (p *OneloginIdentityProvider) oneloginStateMfaPrompt() error {
    if p.mfaDeviceInfo.PromptFunc == nil {
        return fmt.Errorf("Received Onelogin Challenge but %s does not support challenging!", p.mfaDeviceInfo.FactorName)
    }

    result, err := p.mfaDeviceInfo.PromptFunc()
    if err != nil {
        return err
    }

    p.otpToken = &result
    p.state = StateMfaVerify

    return nil
}

type oneloginErrorStatus struct {
    errorCode    int    `json:"code,omitempty"`
    errorType    string `json:"type,omitempty"`
    errorMessage string `json:"message,omitempty"`
}

func (p oneloginErrorStatus) Error() string {
    return fmt.Sprintf("error %d %s - %v", p.errorCode, p.errorType, p.errorMessage)
}

func oneloginAuthError(response *http.Response, responseBody []byte) error {
    errorResponse := make(map[string]interface{}, 0)
    if err := json.Unmarshal(responseBody, &errorResponse); err != nil {
        return oneloginErrorStatus{
            errorCode:    response.StatusCode,
            errorType:    "response body garbled",
            errorMessage: string(responseBody),
        }
    }

    if statusResponse, ok := errorResponse["status"]; ok {
        var errorStatus oneloginErrorStatus
        if status, ok := statusResponse.(map[string]interface{}); ok {
            errorStatus.errorType = status["type"].(string)
            errorStatus.errorCode = int(status["code"].(float64))
            errorStatus.errorMessage = status["message"].(string)
            return errorStatus
        }
    }

    return oneloginErrorStatus{
        errorCode:    response.StatusCode,
        errorType:    "response body invalid",
        errorMessage: fmt.Sprintf("%v", errorResponse),
    }
}

func (p *OneloginIdentityProvider) auth() *string {
    if p.token != nil && p.tokenType != nil {
        return toSP(*p.tokenType + " " + *p.token)
    }
    return nil
}

func oneloginPost(url string, auth *string, body []byte) ([]byte, error) {

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
    if err != nil {
        return nil, err
    }

    req.Header.Set("Accept", "application/json")
    req.Header.Set("Cache-Control", "no-store")
    req.Header.Set("Content-Type", "application/json")

    if auth != nil {
        req.Header.Set("Authorization", *auth)
    }

    response, err := oneloginClient.Do(req)
    if err != nil {
        return nil, err
    }

    defer response.Body.Close()

    responseBody, err := ioutil.ReadAll(response.Body)
    if err != nil {
        return nil, err
    }

    if response.StatusCode != 200 {
        return nil, oneloginAuthError(response, responseBody)
    }

    return responseBody, nil
}

//
// Profile settings
//

type OneloginProfileSettings struct {
    authMethod   *string `validate:"omitempty,oneof=push totp sms email"`
    clientId     *string `validate:"omitempty"`
    clientSecret *string `validate:"omitempty"`
    appId        *string `validate:"omitempty"`
    apiUrl       *string `validate:"omitempty, url"`
}

func (p *OneloginProfileSettings) Create() IdpProfile {
    return &OneloginProfileSettings{}
}

func (p *OneloginProfileSettings) Validate() error {
    return validate.Struct(p)
}

func (p *OneloginProfileSettings) Log(profileName *string) {
    logStringSetting(profilePrompt(profileName, labelOneloginAuthMethod), p.authMethod)
    logStringSetting(profilePrompt(profileName, labelOneloginClientId), p.clientId)
    logStringSetting(profilePrompt(profileName, labelOneloginAppId), p.appId)
    logStringSetting(profilePrompt(profileName, labelOneloginApiUrl), p.apiUrl)
}

func (p *OneloginProfileSettings) Prompt(rootProfileName *string, flagConfigProvider ConfigProvider, identityProviders map[string]IdpProfile) error {

    var defaults *OneloginProfileSettings

    if defaultSettings, ok := identityProviders[oneloginName]; ok {
        defaults = defaultSettings.(*OneloginProfileSettings)
    } else {
        defaults = p.Create().(*OneloginProfileSettings)
    }

    p.authMethod = evaluateString(labelOneloginAuthMethod,
        flagConfigProvider(flagSetOneloginAuthMethod),
        interactiveMenu(profilePrompt(rootProfileName, labelOneloginAuthMethod), oneloginAuthMethods, defaults.authMethod))

    p.clientId = evaluateString(labelOneloginClientId,
        flagConfigProvider(flagSetOneloginClientId),
        interactiveStringValue(profilePrompt(rootProfileName, labelOneloginClientId), defaults.clientId, nil))

    p.clientSecret = evaluateString(labelOneloginClientSecret,
        flagConfigProvider(flagSetOneloginClientSecret),
        interactiveStringValue(profilePrompt(rootProfileName, labelOneloginClientSecret), defaults.clientSecret, nil))

    p.appId = evaluateString(labelOneloginAppId,
        flagConfigProvider(flagSetOneloginAppId),
        interactiveStringValue(profilePrompt(rootProfileName, labelOneloginAppId), defaults.appId, nil))

    p.apiUrl = evaluateString(labelOneloginApiUrl,
        flagConfigProvider(flagSetOneloginApiUrl),
        interactiveStringValue(profilePrompt(rootProfileName, labelOneloginApiUrl), defaults.apiUrl, nil))

    return nil
}

func (p *OneloginProfileSettings) Load(s *viper.Viper) {
    p.authMethod = getString(s, profileKeyOneloginAuthMethod)
    p.clientId = getString(s, profileKeyOneloginClientId)
    p.clientSecret = getString(s, profileKeyOneloginClientSecret)
    p.appId = getString(s, profileKeyOneloginAppId)
    p.apiUrl = getString(s, profileKeyOneloginApiUrl)
}

func (p *OneloginProfileSettings) Store(tree *toml.Tree, prefix string) error {
    if err := setString(tree, prefix+profileKeyOneloginAuthMethod, p.authMethod); err != nil {
        return err
    }

    if err := setString(tree, prefix+profileKeyOneloginClientId, p.clientId); err != nil {
        return err
    }

    if err := setString(tree, prefix+profileKeyOneloginClientSecret, p.clientSecret); err != nil {
        return err
    }

    if err := setString(tree, prefix+profileKeyOneloginAppId, p.appId); err != nil {
        return err
    }

    if err := setString(tree, prefix+profileKeyOneloginApiUrl, p.apiUrl); err != nil {
        return err
    }

    return nil
}

package ofa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xpath"
	"github.com/manifoldco/promptui"
	"github.com/pelletier/go-toml"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// set value flags

	flagSetOktaAuthMethod = "set-okta-auth-method"
	flagSetOktaAppURL     = "set-okta-app-url"

	// value flags

	flagOktaAuthMethod = "okta-auth-method"
	flagOktaAppURL     = "okta-app-url"

	flagDescSetOktaAuthMethod = "Sets the Okta Auth method."
	flagDescSetOktaAppURL     = "Sets the Okta AWS app URL."

	flagDescOktaAuthMethod = "Okta Auth method to use."
	flagDescOktaAppURL     = "Okta AWS app URL to use."

	// profile config keys

	profileKeyOktaAuthMethod = "okta_auth_method"
	profileKeyOktaAppURL     = "okta_app_url"

	// profile labels

	labelOktaAuthMethod = "Okta auth method"
	labelOktaAppURL     = "Okta AWS app URL"
)

type oktaFactorInfo struct {
	name       string
	prompt     string
	factorType string
	promptFunc func() (string, error)
}

var (
	samlPath   *xpath.Expr
	oktaJar    *cookiejar.Jar
	oktaClient *http.Client

	oktaFactorTypes = []*oktaFactorInfo{
		{
			name:       "Okta Verify",
			prompt:     "Push notification",
			factorType: "push",
		},
		{
			name:       "Okta SMS",
			prompt:     "Text Message",
			factorType: "sms",
			promptFunc: func() (string, error) {
				prompt := promptui.Prompt{
					Label: "Enter SMS code",
				}
				result, err := prompt.Run()

				return result, err
			},
		},
		{
			name:       "Google Authenticator",
			prompt:     "TOTP (Google Authenticator, Authy)",
			factorType: "token:software:totp",
			promptFunc: func() (string, error) {
				prompt := promptui.Prompt{
					Label: "Enter OTP token",
				}
				result, err := prompt.Run()

				return result, err
			},
		},
		{
			factorType: "",
			prompt:     "<unset>",
		},
	}

	oktaAuthMethods = make(map[string]*string, 0)
	oktaAuthInfo    = make(map[string]*oktaFactorInfo, 0)
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
	oktaJar, _ = cookiejar.New(
		&cookiejar.Options{})

	oktaClient = &http.Client{
		Jar: oktaJar,
	}

	for _, factorType := range oktaFactorTypes {
		if len(factorType.factorType) > 0 {
			oktaAuthMethods[factorType.prompt] = &factorType.factorType
			oktaAuthInfo[strings.ToLower(factorType.factorType)] = factorType
		} else {
			oktaAuthMethods[factorType.prompt] = nil
		}
	}
}

/*
 * Okta logic
 */

type OktaIdentityProvider struct {
	AppURL     *url.URL `validate:"required,url"`
	AuthMethod *string  `validate:"omitempty,oneof=totp sms push"`

	config     *LoginSession
	mfaFactor  *oktaAuthFactor
	factorInfo *oktaFactorInfo

	state           string
	authTransaction *oktaAuthTransaction
	correctAnswer   *string
	samlData        *string
}

func (p *OktaIdentityProvider) name() string {
	return "Okta"
}

func (p *OktaIdentityProvider) providerProfile() IdpProfile {
	return &OktaProfileSettings{}
}

func (p *OktaIdentityProvider) ConfigurationFlags(flags *pflag.FlagSet) {
	flags.String(flagSetOktaAppURL, "", flagDescSetOktaAppURL)
	flags.String(flagSetOktaAuthMethod, "", flagDescSetOktaAuthMethod)
}

func (p *OktaIdentityProvider) OverrideFlags(flags *pflag.FlagSet) {
	flags.String(flagOktaAppURL, "", flagDescOktaAppURL)
	flags.String(flagOktaAuthMethod, "", flagDescOktaAuthMethod)
}

type OktaProfileSettings struct {
	appUrl     *string `validate:"omitempty,url"`
	authMethod *string `validate:"omitempty,oneof=totp sms push"`
}

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

// see https://developer.okta.com/docs/reference/api/authn/#authentication-transaction-object
//
type oktaAuthTransaction struct {
	StateToken   string     `json:"stateToken"`
	SessionToken string     `json:"sessionToken"`
	ExpiresAt    *time.Time `json:"expiresAt"`
	Status       string     `json:"status"`
	FactorResult string     `json:"factorResult"`

	Embedded oktaEmbedded            `json:"_embedded"`
	Links    map[string]oktaLinkList `json:"_links"`
}

func (oar oktaAuthTransaction) String() string {
	return fmt.Sprintf("ExpiresAt: %s, StateToken: %s, Status: %s", oar.ExpiresAt, oar.StateToken, oar.Status)
}

type oktaEmbedded struct {
	Challenge oktaChallenge    `json:"challenge"`
	Factor    []oktaAuthFactor `json:"factors"`
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
	Embedded   oktaEmbedded        `json:"_embedded"`
}

// oktaChallenge for 3-number verification answer
type oktaChallenge struct {
	CorrectAnswer *string `json:"correctAnswer,omitempty"`
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

func (p *OktaIdentityProvider) Configure(config *LoginSession) error {
	var err error

	p.config = config
	p.AppURL, err = getURL(evaluateString(labelOktaAppURL,
		config.flagConfig(flagOktaAppURL),
		config.profileConfig(profileKeyOktaAppURL),
		config.rootConfig(profileKeyOktaAppURL),
		interactiveStringValue(labelOktaAppURL, nil, validateURL)))

	if err != nil {
		return err
	}

	p.AuthMethod = evaluateString(labelOktaAuthMethod,
		config.flagConfig(flagOktaAuthMethod),
		config.profileConfig(profileKeyOktaAuthMethod),
		config.rootConfig(profileKeyOktaAuthMethod),
		interactiveMenu(labelOktaAuthMethod, oktaAuthMethods, nil))

	return validate.Struct(p)
}

func (p *OktaIdentityProvider) Validate() error {
	return nil
}

func (p *OktaIdentityProvider) Login() (*string, error) {

	Information("**** Logging into Okta")

	p.state = StateLogin
	p.authTransaction = new(oktaAuthTransaction)
	var err error = nil
	for {
		if err != nil {
			return nil, err
		}

		switch p.state {
		case StateSuccess:
			return p.samlData, nil
		case StateSamlAssert:
			err = p.oktaInitiateSamlSession()
		case StateLogin:
			err = p.generateOktaLoginToken()
		case StateMfaRequired:
			err = p.oktaMfaInitiate()
		case StateMfaChallenge:
			err = p.oktaStateMfaChallenge()
		default:
			return nil, fmt.Errorf("okta Session status: %s", p.state)
		}
	}
}

func (p *OktaIdentityProvider) generateOktaLoginToken() error {
	postJSON, err := json.Marshal(oktaAuthRequest{p.config.User, *p.config.Password})
	if err != nil {
		return err
	}

	authnURL, err := p.config.URL.Parse("/api/v1/authn")
	if err != nil {
		return err
	}

	response, err := oktaPost(authnURL.String(), postJSON)
	if err != nil {
		return err
	}

	err = json.Unmarshal(response, p.authTransaction)
	if err != nil {
		return err
	}

	// okta state drives the state machine forward
	return p.nextOktaState()
}

func (p *OktaIdentityProvider) nextOktaState() error {
	// see https://developer.okta.com/docs/reference/api/authn/#transaction-state

	switch p.authTransaction.Status {
	case "SUCCESS":
		p.state = StateSamlAssert
	case "MFA_REQUIRED":
		p.state = StateMfaRequired
	case "MFA_CHALLENGE":
		p.state = StateMfaChallenge
	default:
		return fmt.Errorf("unsupported Okta Session status: %s", p.authTransaction.Status)
	}

	return nil
}

func (p *OktaIdentityProvider) oktaMfaInitiate() error {
	Information("**** Initiating MFA Challenge")

	candidates := make([]oktaAuthFactor, 0)

	for _, factor := range p.authTransaction.Embedded.Factor {
		if oktaFactor, ok := oktaAuthInfo[strings.ToLower(factor.FactorType)]; ok {
			if p.AuthMethod == nil || strings.ToLower(*p.AuthMethod) == oktaFactor.factorType {
				candidates = append(candidates, factor)
			}
		} else {
			log.Errorf("unknown Factor type '%s' encountered, ignoring", factor.FactorType)
		}
	}

	switch len(candidates) {
	case 0:
		return fmt.Errorf("authentication using MFA requested, but no available factor found")
	case 1:
		p.mfaFactor = &candidates[0]
	default:
		result, err := oktaAuthMethodMenuSelector("Select MFA Method", candidates)
		if err != nil {
			return err
		}
		p.mfaFactor = result
	}

	p.factorInfo = oktaAuthInfo[strings.ToLower(p.mfaFactor.FactorType)]

	postJSON, err := json.Marshal(oktaAuthVerify{StateToken: p.authTransaction.StateToken})
	if err != nil {
		return err
	}

	response, err := oktaPost(p.mfaFactor.Links["verify"].Href, postJSON)
	if err != nil {
		return err
	}

	err = json.Unmarshal(response, p.authTransaction)
	if err != nil {
		return err
	}

	err = p.nextOktaState()

	return err
}

func (p *OktaIdentityProvider) oktaStateMfaChallenge() error {

	challengeResponse := oktaAuthVerify{StateToken: p.authTransaction.StateToken}

	// based on the result of the *previous* interaction with the API, choose an action. If the previous
	// interaction resulted e.g. in CHALLENGE, prompt the user for the necessary factor.
	switch p.authTransaction.FactorResult {
	case "CHALLENGE":
		if p.factorInfo.promptFunc == nil {
			return fmt.Errorf("received Okta Challenge but %s does not support challenging", p.mfaFactor.FactorType)
		}

		result, err := p.factorInfo.promptFunc()
		if err != nil {
			return err
		}

		challengeResponse.PassCode = &result
	case "WAITING":
		time.Sleep(1 * time.Second)

		// find factor to see whether there is an additional challenge
		if p.correctAnswer == nil {
			for _, factor := range p.authTransaction.Embedded.Factor {
				if factor.ID == p.mfaFactor.ID {
					if factor.Embedded.Challenge.CorrectAnswer != nil {
						p.correctAnswer = factor.Embedded.Challenge.CorrectAnswer
						fmt.Printf("Okta 3-number verification, correct answer is %s", *p.correctAnswer)
						return nil
					}
				}
			}
		}

	case "CANCELLED":
	case "REJECTED":
		return fmt.Errorf("aborted by user")
	default:
		return fmt.Errorf("factor challenge returned %s, aborting", p.authTransaction.FactorResult)
	}

	postJSON, err := json.Marshal(challengeResponse)
	if err != nil {
		return err
	}

	response, err := oktaPost(p.authTransaction.Links["next"].links[0].Href, postJSON)
	if err != nil {
		return err
	}

	err = json.Unmarshal(response, p.authTransaction)
	if err != nil {
		return err
	}

	return p.nextOktaState()
}

func (p *OktaIdentityProvider) oktaInitiateSamlSession() (err error) {
	Information("**** Fetching Okta SAML response")

	u := p.AppURL
	q := u.Query()
	q.Set("sessionToken", p.authTransaction.SessionToken)
	p.AppURL.RawQuery = q.Encode()

	response, err := oktaGet(u.String())
	if err != nil {
		return err
	}

	// yeah, this is terrible. It is also the official way according to
	// https://developer.okta.com/docs/guides/session-cookie/overview/#retrieving-a-session-cookie-via-openid-connect-authorization-endpoint
	// improvement wanted!
	htmlDoc, err := htmlquery.Parse(bytes.NewReader(response))
	if err != nil {
		return err
	}

	p.samlData = toSP(samlPath.Evaluate(htmlquery.CreateXPathNavigator(htmlDoc)).(string))
	p.state = StateSuccess
	return nil
}

func oktaAuthMethodMenuSelector(label string, authFactors []oktaAuthFactor) (*oktaAuthFactor, error) {
	m := make(map[string]*oktaAuthFactor, len(authFactors))
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

func oktaAuthError(response *http.Response, responseBody []byte) error {
	var errorResponse oktaErrorResponse
	if err := json.Unmarshal(responseBody, &errorResponse); err != nil {
		return fmt.Errorf("okta response body garbled")
	}

	if response.StatusCode == 401 {
		return fmt.Errorf("could not log into Okta: %s", errorResponse.ErrorSummary)
	}

	return fmt.Errorf("okta error (%d) - %s", response.StatusCode, errorResponse.ErrorSummary)
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

//
// Profile settings
//

func (p *OktaProfileSettings) Create() IdpProfile {
	return &OktaProfileSettings{}
}

func (p *OktaProfileSettings) Validate() error {
	return validate.Struct(p)
}

func (p *OktaProfileSettings) Log(profileName *string) {
	logStringSetting(profilePrompt(profileName, labelOktaAuthMethod), p.authMethod)
	logStringSetting(profilePrompt(profileName, labelOktaAppURL), p.appUrl)
}

func (p *OktaProfileSettings) Prompt(rootProfileName *string, flagConfigProvider ConfigProvider, identityProviders map[string]IdpProfile) error {

	var defaults *OktaProfileSettings

	if defaultSettings, ok := identityProviders[oktaName]; ok {
		defaults = defaultSettings.(*OktaProfileSettings)
	} else {
		defaults = p.Create().(*OktaProfileSettings)
	}

	p.appUrl = evaluateString(labelOktaAppURL,
		flagConfigProvider(flagSetOktaAppURL),
		interactiveStringValue(profilePrompt(rootProfileName, labelOktaAppURL), defaults.appUrl, validateURL))

	p.authMethod = evaluateString(labelOktaAuthMethod,
		flagConfigProvider(flagSetOktaAuthMethod),
		interactiveMenu(profilePrompt(rootProfileName, labelOktaAuthMethod), oktaAuthMethods, defaults.authMethod))

	return nil
}

func (p *OktaProfileSettings) Load(s *viper.Viper) {

	p.appUrl = getString(s, profileKeyOktaAppURL)
	p.authMethod = getString(s, profileKeyOktaAuthMethod)
}

func (p *OktaProfileSettings) Store(tree *toml.Tree, prefix string) error {
	if err := setString(tree, prefix+profileKeyOktaAppURL, p.appUrl); err != nil {
		return err
	}
	if err := setString(tree, prefix+profileKeyOktaAuthMethod, p.authMethod); err != nil {
		return err
	}
	return nil
}

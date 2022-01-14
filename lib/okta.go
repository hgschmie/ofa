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

var (
	samlPath   *xpath.Expr
	oktaClient *http.Client

	oktaAuthMethods = map[string]*string{
		"Push Notification":                  toSP("push"),
		"Text Message":                       toSP("sms"),
		"TOTP (Google Authenticator, Authy)": toSP("totp"),
		"<unset>":                            nil,
	}

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
		"token:software:totp": {"totp",
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

type OktaIdentityProvider struct {
	AppURL     *url.URL `validate:"required,url"`
	AuthMethod *string  `validate:"omitempty,oneof=totp sms push"`
	config     *LoginSession
	mfaFactor  *oktaAuthFactor
	factorInfo *factorInfo
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

type factorInfo struct {
	FactorName string
	Prompt     func() (string, error)
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

	postJSON, err := json.Marshal(oktaAuthRequest{p.config.User, *p.config.Password})
	if err != nil {
		return nil, err
	}

	authnURL, err := p.config.URL.Parse("/api/v1/authn")
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
			authTransaction, err = p.mfaInitiate(authTransaction)
		case "MFA_CHALLENGE":
			authTransaction, err = p.mfaChallenge(authTransaction)
		case "SUCCESS":
			Information("**** Okta login successful")
			return p.oktaInitiateSamlSession(authTransaction)
		default:
			return nil, fmt.Errorf("Okta Session status: %s", authTransaction.SessionToken)
		}
	}
}

func (p *OktaIdentityProvider) oktaInitiateSamlSession(authTransaction *oktaAuthTransaction) (samlResponse *string, err error) {
	Information("**** Fetching Okta SAML response")

	u := p.AppURL
	q := u.Query()
	q.Set("sessionToken", authTransaction.SessionToken)
	p.AppURL.RawQuery = q.Encode()

	response, err := oktaGet(u.String())
	if err != nil {
		return nil, err
	}

	// yeah, this is terrible. It is also the official way according to
	// https://developer.okta.com/docs/guides/session-cookie/overview/#retrieving-a-session-cookie-via-openid-connect-authorization-endpoint
	// improvement wanted!
	htmlDoc, err := htmlquery.Parse(bytes.NewReader(response))
	if err != nil {
		return nil, err
	}

	return toSP(samlPath.Evaluate(htmlquery.CreateXPathNavigator(htmlDoc)).(string)), nil
}

func (p *OktaIdentityProvider) mfaInitiate(authTransaction *oktaAuthTransaction) (*oktaAuthTransaction, error) {
	Information("**** Initiating MFA Challenge")

	candidates := make([]oktaAuthFactor, 0)

	for _, factor := range authTransaction.Embedded.Factor {
		if oktaFactor, ok := oktaTypes[strings.ToLower(factor.FactorType)]; ok {
			if p.AuthMethod == nil || strings.ToLower(*p.AuthMethod) == oktaFactor.FactorName {
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
		p.mfaFactor = &candidates[0]
	default:
		result, err := oktaAuthMethodMenuSelector("Select MFA Method", candidates)
		if err != nil {
			return nil, err
		}
		p.mfaFactor = result
	}

	p.factorInfo = oktaTypes[strings.ToLower(p.mfaFactor.FactorType)]

	postJSON, err := json.Marshal(oktaAuthVerify{StateToken: authTransaction.StateToken})
	if err != nil {
		return nil, err
	}

	response, err := oktaPost(p.mfaFactor.Links["verify"].Href, postJSON)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(response, authTransaction)
	if err != nil {
		return nil, err
	}

	return authTransaction, nil
}

func (p *OktaIdentityProvider) mfaChallenge(authTransaction *oktaAuthTransaction) (*oktaAuthTransaction, error) {
	challengeResponse := oktaAuthVerify{StateToken: authTransaction.StateToken}

	// based on the result of the *previous* interaction with the API, choose an action. If the previous
	// interaction resulted e.g. in CHALLENGE, prompt the user for the necessary factor.
	switch authTransaction.FactorResult {
	case "CHALLENGE":
		if p.factorInfo.Prompt == nil {
			return nil, fmt.Errorf("Received Okta Challenge but %s does not support challenging!", p.mfaFactor.FactorType)
		}

		result, err := p.factorInfo.Prompt()
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

	return fmt.Errorf("Okta Error (%d) - %s", response.StatusCode, errorResponse.ErrorSummary)
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

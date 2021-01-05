package ofa

import (
    "bytes"
    "encoding/base64"
    "fmt"
    "strings"

    "github.com/antchfx/htmlquery"
    "github.com/antchfx/xmlquery"
    "github.com/antchfx/xpath"
    "github.com/aws/aws-sdk-go/aws/arn"
    log "github.com/sirupsen/logrus"
)

var (
    rolePath    *xpath.Expr
    sessionPath *xpath.Expr
)

func init() {
    var err error
    rolePath, err = xpath.Compile("//saml2:Assertion/saml2:AttributeStatement/saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml2:AttributeValue")
    if err != nil {
        log.Panic("Error compile role path!")
    }
    sessionPath, err = xpath.Compile("number(//saml2:Assertion/saml2:AttributeStatement/saml2:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/SessionDuration']/saml2:AttributeValue)")
    if err != nil {
        log.Panic("Error compile session path!")
    }
}

type samlAwsRole struct {
    PrincipalArn arn.ARN
    RoleArn      arn.ARN
    SessionTime  int64 // The SAML Request contains a session time, but this is not usable as the AWS roles may be configured to a different max session duration.
}

func (role samlAwsRole) String() string {
    return strings.TrimPrefix(role.RoleArn.Resource, "role/")
}

func newSamlAwsRole(s string, sessionDuration int64) (*samlAwsRole, error) {
    roleText := strings.Split(s, ",")
    if len(roleText) != 2 {
        return nil, fmt.Errorf("Found bad role text: %s", roleText)
    }

    var err error
    result := &samlAwsRole{SessionTime: sessionDuration}

    result.PrincipalArn, err = arn.Parse(roleText[0])
    if err != nil {
        return nil, err
    }
    result.RoleArn, err = arn.Parse(roleText[1])
    if err != nil {
        return nil, err
    }

    return result, nil
}

func OktaSamlSession(session *LoginSession, sessionToken string) (samlResponse *string, err error) {

    Information("**** Fetching Okta SAML response")

    u := session.OktaAppURL
    q := u.Query()
    q.Set("sessionToken", sessionToken)
    session.OktaAppURL.RawQuery = q.Encode()

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

func SelectAwsRoleFromSaml(session *LoginSession, saml *string) (*samlAwsRole, error) {

    Information("**** Selecting AWS role from SAML response")

    samlDoc, err := base64.StdEncoding.DecodeString(*saml)
    if err != nil {
        return nil, err
    }

    xmlDoc, err := xmlquery.Parse(bytes.NewReader(samlDoc))
    if err != nil {
        return nil, err
    }

    roles := rolePath.Select(xmlquery.CreateXPathNavigator(xmlDoc))

    sessionDuration := int64(sessionPath.Evaluate(xmlquery.CreateXPathNavigator(xmlDoc)).(float64))

    var arnRoles []samlAwsRole

    for roles.MoveNext() {
        nodeText := roles.Current().Value()
        roleAssertion, err := newSamlAwsRole(nodeText, sessionDuration)
        if err != nil {
            return nil, err
        }

        if session.AwsRole == nil || strings.ToLower(*session.AwsRole) == strings.ToLower(roleAssertion.String()) {
            arnRoles = append(arnRoles, *roleAssertion)
        }
    }

    var arnRole *samlAwsRole

    switch len(arnRoles) {
    case 0:
        log.Fatal("No usable roles associated with this account, can not log into AWS!")
    case 1:
        arnRole = &arnRoles[0]
    default:
        result, err := awsRoleMenuSelector("Select AWS Role", arnRoles)
        if err != nil {
            return nil, err
        }
        arnRole = result
    }
    return arnRole, nil
}

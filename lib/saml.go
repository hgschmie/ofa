package ofa

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	"github.com/aws/aws-sdk-go/aws/arn"
	log "github.com/sirupsen/logrus"
	"strings"
)

var (
	rolePath    *xpath.Expr
	sessionPath *xpath.Expr
)

const (
	samlNs                 = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlAssertion          = "*[namespace-uri()='" + samlNs + "' and local-name()='Assertion']"
	samlAttributeStatement = "*[namespace-uri()='" + samlNs + "' and local-name()='AttributeStatement']"
	samlAttribute          = "*[namespace-uri()='" + samlNs + "' and local-name()='Attribute']"
	samlAttributeValue     = "*[namespace-uri()='" + samlNs + "' and local-name()='AttributeValue']"
)

func init() {
	var err error

	rolePath, err = xpath.Compile("//" + samlAssertion + "/" + samlAttributeStatement + "/" + samlAttribute + "[@Name='https://aws.amazon.com/SAML/Attributes/Role']/" + samlAttributeValue)
	if err != nil {
		log.Panic("Error compile role path!")
	}
	sessionPath, err = xpath.Compile("number(//" + samlAssertion + "/" + samlAttributeStatement + "/" + samlAttribute + "[@Name='https://aws.amazon.com/SAML/Attributes/SessionDuration']/" + samlAttributeValue + ")")
	if err != nil {
		log.Panic("Error compile session path!")
	}
}

type samlAwsRole struct {
	PrincipalArn *arn.ARN
	RoleArn      *arn.ARN
	AccountName  *string
	SessionTime  int64 // The SAML Request contains a session time, but this is not usable as the AWS roles may be configured to a different max session duration.
}

func (role samlAwsRole) String() string {
	return strings.TrimPrefix(role.RoleArn.Resource, "role/")
}

func (role samlAwsRole) AccountId() string {
	return role.RoleArn.AccountID
}

func (role samlAwsRole) DisplayName() string {
	if role.AccountName != nil {
		return *role.AccountName
	} else {
		return role.AccountId()
	}
}

func newSamlAwsRole(s string, sessionDuration int64) (*samlAwsRole, error) {
	roleText := strings.Split(s, ",")
	if len(roleText) < 2 {
		return nil, fmt.Errorf("Found bad role text: %s", roleText)
	}

	result := &samlAwsRole{SessionTime: sessionDuration}

	for _, role := range roleText {
		roleArn, err := arn.Parse(role)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(roleArn.Resource, "role/") {
			result.RoleArn = &roleArn
		} else if strings.HasPrefix(roleArn.Resource, "saml-provider/") {
			result.PrincipalArn = &roleArn
		}
	}

	if result.PrincipalArn == nil {
		return nil, fmt.Errorf("No principal (saml-provider) ARN found (%s)", s)
	}
	if result.RoleArn == nil {
		return nil, fmt.Errorf("No role ARN found (%s)", s)
	}

	return result, nil
}

func SelectAwsRoleFromSaml(session *LoginSession, saml *string, roleSelection bool) (*samlAwsRole, error) {

	Information("**** Selecting AWS role from SAML response")

	samlDoc, err := base64.StdEncoding.DecodeString(*saml)
	if err != nil {
		return nil, err
	}

	xmlDoc, err := xmlquery.Parse(bytes.NewReader(samlDoc))
	if err != nil {
		return nil, err
	}

	query := xmlquery.CreateXPathNavigator(xmlDoc)

	roles := rolePath.Select(query)

	sessionDuration := int64(sessionPath.Evaluate(xmlquery.CreateXPathNavigator(xmlDoc)).(float64))

	var allRoles []samlAwsRole

	// are roles from more than one account present?
	multiAccount := false
	var accountIdSeen *string = nil

	for roles.MoveNext() {
		nodeText := roles.Current().Value()
		samlRole, err := newSamlAwsRole(nodeText, sessionDuration)
		if err != nil {
			return nil, err
		}

		// try populating the Account name
		if err := populateAccountName(samlRole, saml); err != nil {
			return nil, err
		}

		if session.AwsRole == nil || roleSelection || strings.ToLower(*session.AwsRole) == strings.ToLower(samlRole.String()) {
			if accountIdSeen == nil {
				accountIdSeen = toSP(samlRole.AccountId())
			} else {
				// seen roles from more than one account -> This is a multi-account role list
				if *accountIdSeen != samlRole.AccountId() {
					multiAccount = true
				}
			}
			allRoles = append(allRoles, *samlRole)
		}
	}

	var arnRole *samlAwsRole

	switch len(allRoles) {
	case 0:
		log.Fatal("No usable roles associated with this account, can not log into AWS!")
	case 1:
		arnRole = &allRoles[0]
	default:
		result, err := awsRoleMenuSelector("Select AWS Role", allRoles, multiAccount)
		if err != nil {
			return nil, err
		}
		arnRole = result
	}
	return arnRole, nil
}

func populateAccountName(role *samlAwsRole, samlResponse *string) error {
	accountCache := stateCache.subStore(stateCacheAwsAccounts)

	accountAlias := getString(accountCache, role.AccountId())
	if accountAlias != nil {
		role.AccountName = accountAlias
		return nil
	}

	accountAlias, err := accountAliasFromSaml(role, samlResponse)

	// return err if err, return nil if error is nil and accountAlias also nil
	if err != nil {
		return err
	}

	if accountAlias == nil {
		role.AccountName = toSP(role.AccountId())
	} else {
		role.AccountName = accountAlias
	}

	if tree, err := stateCache.loadConfigFile(); err == nil {
		if err = setString(tree, stateCacheAwsAccounts+"."+role.AccountId(), accountAlias); err == nil {
			_ = stateCache.storeConfigFile(tree)
		}
	}
	return nil
}

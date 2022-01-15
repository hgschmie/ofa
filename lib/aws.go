package ofa

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-ini/ini"
	log "github.com/sirupsen/logrus"
	"path/filepath"
)

func init() {
	var err error

	awsConfig := aws.NewConfig().WithCredentialsChainVerboseErrors(true)
	awsOptions := session.Options{
		Config:            *awsConfig,
		SharedConfigState: session.SharedConfigDisable,
	}

	awsSession, err = session.NewSessionWithOptions(awsOptions)
	if err != nil {
		log.Panicf("Could not create AWS Session: %v", err)
	}

	stsClient = sts.New(awsSession)
}

const (
	awsAccessKeyId     = "aws_access_key_id"
	awsSecretAccessKey = "aws_secret_access_key"
	awsSessionToken    = "aws_session_token"
)

var (
	awsSession *session.Session
	stsClient  *sts.STS
)

// AssumeAwsRole takes the SAML credentials and assumes an AWS role
func AssumeAwsRole(samlResponse *string, samlAwsRole *samlAwsRole, sessionTime *int64) (*credentials.Credentials, error) {
	Information("**** Assuming AWS role '%s'", samlAwsRole.RoleArn)

	input := &sts.AssumeRoleWithSAMLInput{}

	if sessionTime != nil {
		input.SetDurationSeconds(*sessionTime)
	}

	err := input.
		SetPrincipalArn(samlAwsRole.PrincipalArn.String()).
		SetRoleArn(samlAwsRole.RoleArn.String()).
		SetSAMLAssertion(*samlResponse).
		Validate()

	if err != nil {
		return nil, err
	}

	req, res := stsClient.AssumeRoleWithSAMLRequest(input)

	err = req.Send()
	if err != nil {
		return nil, err
	}

	creds := credentials.NewStaticCredentials(*res.Credentials.AccessKeyId, *res.Credentials.SecretAccessKey, *res.Credentials.SessionToken)

	return creds, nil
}

func accountAliasFromSaml(role *samlAwsRole, samlResponse *string) (*string, error) {

	roleCredentials, err := AssumeAwsRole(samlResponse, role, nil)
	if err != nil {
		return nil, err
	}

	awsRoleConfig := aws.NewConfig().
		WithCredentialsChainVerboseErrors(true).
		WithCredentials(roleCredentials)

	awsRoleOptions := session.Options{
		Config:            *awsRoleConfig,
		SharedConfigState: session.SharedConfigDisable,
	}

	awsRoleSession, err := session.NewSessionWithOptions(awsRoleOptions)

	if err != nil {
		return nil, err
	}

	iamClient := iam.New(awsRoleSession)

	iamInput := &iam.ListAccountAliasesInput{}
	iamOutput, err := iamClient.ListAccountAliases(iamInput)
	if err != nil {
		return nil, err
	}

	if len(iamOutput.AccountAliases) > 0 {
		return iamOutput.AccountAliases[0], nil
	}

	return nil, nil
}

// WriteAwsCredentials writes the credentials for the AWS profile selected into the AWS config files.
func WriteAwsCredentials(session *LoginSession, cred *credentials.Credentials) error {
	Information("**** Writing AWS credentials file")

	fileName := awsCredentialsFilename(homeDir)

	cfg, err := ini.LooseLoad(fileName)
	if err != nil {
		return err
	}

	// remove all keys from the section. If this is an existing section, it keeps
	// it in order. Otherwise, this could just be cfg.DeleteSection() ; cfg.NewSection()
	section := cfg.Section(session.ProfileName)
	for _, key := range section.KeyStrings() {
		section.DeleteKey(key)
	}

	v, err := cred.Get()
	if err != nil {
		return err
	}

	_, err = section.NewKey(awsAccessKeyId, v.AccessKeyID)
	if err != nil {
		return err
	}
	_, err = section.NewKey(awsSecretAccessKey, v.SecretAccessKey)
	if err != nil {
		return err
	}
	_, err = section.NewKey(awsSessionToken, v.SessionToken)
	if err != nil {
		return err
	}

	// the okta-aws-cli-assume-role tool also wrote a aws_security_token entry for some really ancient versions of boto.

	err = storeFile(fileName, func(filename string) error {
		return cfg.SaveTo(filename)
	})

	Information("**** AWS credentials file written")
	return err
}

func awsCredentialsFilename(homeDir *string) string {
	return filepath.Join(*homeDir, ".aws", "credentials")
}

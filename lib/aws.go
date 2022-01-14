package ofa

import (
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-ini/ini"
	log "github.com/sirupsen/logrus"
)

func init() {
	var err error

	homeDir, err = userHomeDir()
	if err != nil {
		log.Panicf("Could not determine home directory: %v", err)
	}

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
	awsAccessKeyId      = "aws_access_key_id"
	awsSecrectAccessKey = "aws_secret_access_key"
	awsSessionToken     = "aws_session_token"
)

var (
	awsSession *session.Session
	stsClient  *sts.STS
	homeDir    *string
)

// AssumeAwsRole takes the SAML credentials and assumes an AWS role
func AssumeAwsRole(session *LoginSession, samlResponse *string, samlAwsRole *samlAwsRole) (*credentials.Credentials, error) {
	Information("**** Assuming AWS role '%s'", samlAwsRole.RoleArn)

	input := &sts.AssumeRoleWithSAMLInput{}

	if session.AwsSessionTime != nil {
		input.SetDurationSeconds(*session.AwsSessionTime)
	}

	err := input.
		SetPrincipalArn(samlAwsRole.PrincipalArn.String()).
		SetRoleArn(samlAwsRole.RoleArn.String()).
		SetSAMLAssertion(*samlResponse).Validate()

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
	_, err = section.NewKey(awsSecrectAccessKey, v.SecretAccessKey)
	if err != nil {
		return err
	}
	_, err = section.NewKey(awsSessionToken, v.SessionToken)
	if err != nil {
		return err
	}

	// the okta-aws-cli-assume-role tool also wrote a aws_security_token entry for some really ancient versions of boto.

	storeFile(fileName, func(filename string) error {
		return cfg.SaveTo(filename)
	})

	Information("**** AWS credentials file written")
	return err
}

func awsCredentialsFilename(homeDir *string) string {
	return filepath.Join(*homeDir, ".aws", "credentials")
}

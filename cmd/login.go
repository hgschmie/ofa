package cmd

/**
 * OktaLogin Command
 */

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	ofa "github.com/hgschmie/ofa/v3/lib"
)

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.Flags().String(ofa.FlagProfile, "", ofa.FlagDescProfile)
	loginCmd.Flags().String(ofa.FlagUser, "", ofa.FlagDescUser)
	loginCmd.Flags().String(ofa.FlagURL, "", ofa.FlagDescURL)

	loginCmd.Flags().String(ofa.FlagProfileType, "", ofa.FlagDescProfileType)
	loginCmd.Flags().String(ofa.FlagPassword, "", ofa.FlagDescPassword)

	for _, v := range ofa.IdentityProviders {
		v.OverrideFlags(loginCmd.Flags())
	}

	loginCmd.Flags().String(ofa.FlagAwsAccount, "", ofa.FlagDescAwsAccount)
	loginCmd.Flags().String(ofa.FlagAwsRole, "", ofa.FlagDescAwsRole)
	loginCmd.Flags().Int64(ofa.FlagSessionTime, 0, ofa.FlagDescSessionTime)

	loginCmd.Flags().BoolVar(&noSave, ofa.FlagEval, false, ofa.FlagDescEval)
	loginCmd.Flags().BoolVar(&noProfile, ofa.FlagNoProfile, false, ofa.FlagDescNoProfile)
	loginCmd.Flags().BoolVar(&roleSelection, ofa.FlagNoRole, false, ofa.FlagDescNoRole)
}

var (
	noSave        = false
	noProfile     = false
	roleSelection = false

	loginCmd = &cobra.Command{
		Use:   "login",
		Short: "Log into a profile",
		Long:  "Use Okta to log into an AWS profile.",
		Run: func(cmd *cobra.Command, args []string) {

			ofa.DisplayGlobalFlags()
			ofa.Information("**** Login Session:")

			config, err := ofa.CreateLoginSession(cmd.Flags(), noProfile)
			if err != nil {
				log.Fatalf("Could not create config: %v", err)
			}

			var loginProvider = config.IdentityProvider

			if err = loginProvider.Validate(); err != nil {
				log.Fatalf("Could not validate config: #{err}")
			}

			samlResponse, err := loginProvider.Login()
			if err != nil {
				log.Fatalf("Could not log into %s: %v", config.ProfileType, err)
			}

			arnRole, err := ofa.SelectAwsRoleFromSaml(config, samlResponse, roleSelection)
			if err != nil {
				log.Fatalf("Could not parse SAML assertion: %v", err)
			}

			creds, err := ofa.AssumeAwsRole(samlResponse, arnRole, config.AwsSessionTime)
			if err != nil {
				log.Fatalf("Could not assume selected AWS role: %v", err)
			}

			// there is code in the original okta-aws-cli-assume-role that lists the policies and
			// may query the user to choose a policy. However, the code is buggy and never worked
			// to no ill effect. So this whole code path (GetRoleToAssume()) is not implemented.

			if !noSave && len(config.ProfileName) > 0 {
				err = ofa.WriteAwsCredentials(config, creds)
				if err != nil {
					log.Fatalf("Could not write config file: %v", err)
				}
			} else {
				v, err := creds.Get()
				if err != nil {
					log.Fatalf("Could not access credentials: %v", err)
				}
				fmt.Printf("AWS_ACCESS_KEY_ID=%s\n", v.AccessKeyID)
				fmt.Printf("AWS_SECRET_ACCESS_KEY=%s\n", v.SecretAccessKey)
				fmt.Printf("AWS_SESSION_TOKEN=%s\n", v.SessionToken)
			}

			ofa.Information("**** Login complete")
			// ------------------
		},
	}
)

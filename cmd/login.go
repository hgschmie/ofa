package cmd

/**
 * OktaLogin Command
 */

import (
    "fmt"

    log "github.com/sirupsen/logrus"
    "github.com/spf13/cobra"

    ofa "github.com/hgschmie/ofa/lib"
)

func init() {
    rootCmd.AddCommand(loginCmd)

    loginCmd.Flags().String(ofa.FlagProfile, "", "The profile to use.")
    loginCmd.Flags().String(ofa.FlagUser, "", ofa.FlagDescUser)
    loginCmd.Flags().String(ofa.FlagPassword, "", ofa.FlagDescPassword)
    loginCmd.Flags().String(ofa.FlagOktaURL, "", ofa.FlagDescOktaURL)
    loginCmd.Flags().String(ofa.FlagOktaAppURL, "", ofa.FlagDescOktaAppURL)
    loginCmd.Flags().String(ofa.FlagAuthMethod, "", ofa.FlagDescAuthMethod)
    loginCmd.Flags().String(ofa.FlagRole, "", ofa.FlagDescRole)
    loginCmd.Flags().Int64(ofa.FlagSessionTime, 0, ofa.FlagDescSessionTime)

    loginCmd.Flags().BoolVar(&noSave, "eval", false, "Do not save AWS credentials, echo on stdout for eval.")
}

var (
    noSave bool = false

    loginCmd = &cobra.Command{
        Use:   "login",
        Short: "Log into a profile",
        Long:  "Use Okta to log into an AWS profile.",
        Run: func(cmd *cobra.Command, args []string) {

            ofa.DisplayGlobalFlags()
            ofa.Information("**** Login Session:")

            config, err := ofa.CreateLoginSession(cmd.Flags())
            if err != nil {
                log.Fatalf("Could not create config: %v", err)
            }

            sessionToken, err := ofa.OktaLogin(config)
            if err != nil {
                log.Fatalf("Could not log into Okta: %v", err)
            }

            samlResponse, err := ofa.OktaSamlSession(config, *sessionToken)
            if err != nil {
                log.Fatalf("Could not parse SAML response: %v", err)
            }

            arnRole, err := ofa.SelectAwsRoleFromSaml(config, samlResponse)
            if err != nil {
                log.Fatalf("Could not parse SAML assertion: %v", err)
            }

            creds, err := ofa.AssumeAwsRole(config, samlResponse, arnRole)
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
                fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", v.AccessKeyID)
                fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", v.SecretAccessKey)
                fmt.Printf("export AWS_SESSION_TOKEN=%s\n", v.SessionToken)
            }

            ofa.Information("**** Okta Login complete")
            // ------------------
        },
    }
)

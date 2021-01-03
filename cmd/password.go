package cmd

import (
    "log"

    "github.com/spf13/cobra"

    ofa "github.com/hgschmie/ofa/lib"
)

func init() {
    rootCmd.AddCommand(passwordCmd)
    passwordCmd.AddCommand(passwordSetCmd)
    passwordCmd.AddCommand(passwordRemoveCmd)

    passwordSetCmd.Flags().String(ofa.FlagProfile, "", "The profile to use.")
    passwordSetCmd.Flags().String(ofa.FlagOktaURL, "", ofa.FlagDescOktaURL)
    passwordSetCmd.Flags().String(ofa.FlagUser, "", ofa.FlagDescUser)
    passwordSetCmd.Flags().String(ofa.FlagPassword, "", ofa.FlagDescPassword)

    passwordRemoveCmd.Flags().String(ofa.FlagProfile, "", "The profile to use.")
    passwordRemoveCmd.Flags().String(ofa.FlagOktaURL, "", ofa.FlagDescOktaURL)
    passwordRemoveCmd.Flags().String(ofa.FlagUser, "", ofa.FlagDescUser)
}

var (
    passwordCmd = &cobra.Command{
        Use:   "password",
        Short: "Manage keychain passwords",
        Long:  "Manage keychain passwords.",
        Run: func(cmd *cobra.Command, args []string) {
            _ = cmd.Usage()
        },
    }

    passwordSetCmd = &cobra.Command{
        Use:   "set",
        Short: "Set a keychain password.",
        Long:  "Set a keychain password.",
        Run: func(cmd *cobra.Command, args []string) {

            password, err := ofa.NewKeychainPassword(cmd.Flags(), true)
            if err != nil {
                log.Fatalf("Could not create password: %v", err)
            }

            if err := password.Update(); err != nil {
                log.Fatalf("Could not store Okta password for %s @ %v: %v", password.User, password.URL, err)
            }
        },
    }

    passwordRemoveCmd = &cobra.Command{
        Use:   "remove",
        Short: "Remove a keychain password.",
        Long:  "Remove a keychain password.",
        Run: func(cmd *cobra.Command, args []string) {

            password, err := ofa.NewKeychainPassword(cmd.Flags(), false)
            if err != nil {
                log.Fatalf("Could not create password: %v", err)
            }

            if err := password.Delete(); err != nil {
                log.Fatalf("Could not remove Okta password for %s @ %v: %v", password.User, password.URL, err)
            }
        },
    }
)

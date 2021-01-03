package cmd

import (
    log "github.com/sirupsen/logrus"
    "github.com/spf13/cobra"

    ofa "github.com/hgschmie/ofa/lib"
)

func init() {
    rootCmd.AddCommand(defaultCmd)
    defaultCmd.AddCommand(defaultShowCmd)
    defaultCmd.AddCommand(defaultSetCmd)

    defaultSetCmd.Flags().Bool(ofa.FlagSetVerbose, true, ofa.FlagDescSetVerbose)
    defaultSetCmd.Flags().Bool(ofa.FlagSetInteractive, true, ofa.FlagDescSetInteractive)
    defaultSetCmd.Flags().String(ofa.FlagSetProfile, "", ofa.FlagDescSetProfileName)
    defaultSetCmd.Flags().String(ofa.FlagSetUser, "", ofa.FlagDescSetUser)
    defaultSetCmd.Flags().String(ofa.FlagSetOktaURL, "", ofa.FlagDescSetOktaURL)
    defaultSetCmd.Flags().String(ofa.FlagSetOktaAppURL, "", ofa.FlagDescSetOktaAppURL)
    defaultSetCmd.Flags().String(ofa.FlagSetAuthMethod, "", ofa.FlagDescSetAuthMethod)
    defaultSetCmd.Flags().String(ofa.FlagSetRole, "", ofa.FlagDescSetRole)
    defaultSetCmd.Flags().Int64(ofa.FlagSetSessionTime, 0, ofa.FlagDescSetSessionTime)
}

var (
    defaultCmd = &cobra.Command{
        Use:   "global",
        Short: "Manage global settings",
        Long:  "Manage global settings.",
        Run: func(cmd *cobra.Command, args []string) {
            _ = cmd.Usage()
        },
    }

    defaultShowCmd = &cobra.Command{
        Use:   "show",
        Short: "Show default settings",
        Long:  "Show default settings.",
        Run: func(cmd *cobra.Command, args []string) {

            defaultSettings, _ := ofa.ListProfiles()
            defaultSettings.Display()
        },
    }

    defaultSetCmd = &cobra.Command{
        Use:   "set",
        Short: "Modify default settings",
        Long:  "Modify default settings.",
        Run: func(cmd *cobra.Command, args []string) {
            ofa.Information("**** Configure Defaults:")

            g, err := ofa.CreateDefaultSettings(cmd.Flags())
            if err != nil {
                log.Fatalf("Could not create global settings: %v", err)
            }

            if err := ofa.StoreDefaultSettings(g); err != nil {
                log.Fatalf("Could not store global settings: %v", err)
            }
        },
    }
)

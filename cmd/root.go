package cmd

import (
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"

	ofa "github.com/hgschmie/ofa/v3/lib"
)

func init() {
	rootCmd.PersistentFlags().Bool(ofa.FlagInteractive, false, "Force prompting for user input if required.")
	rootCmd.PersistentFlags().Bool(ofa.FlagBatch, false, "Never prompt for user input if required.")
	rootCmd.PersistentFlags().Bool(ofa.FlagVerbose, false, "Report additional information while executing.")
	rootCmd.PersistentFlags().Bool(ofa.FlagQuiet, false, "Do not output any information while executing.")
	rootCmd.PersistentFlags().Bool(ofa.FlagNoConfig, false, "Ignore configuration files.")
}

var (
	rootCmd = &cobra.Command{
		Use:   "ofa",
		Short: "ofa is the Okta AWS authentication manager",
		Long:  "ofa manages Okta Logins and AWS profiles to authenticate to AWS using Okta.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Usage()
		},

		PersistentPreRun: func(command *cobra.Command, args []string) {
			if command.Name() != "help" {
				err := ofa.LoadConfig()
				if err != nil {
					log.Fatalf("Could not load configuration file: %v", err)
				}

				ofa.SetGlobalFlags(command.Flags())
			}
		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Command execution failed: %v", err)
	}

}

package cmd

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	ofa "github.com/hgschmie/ofa/lib"
)

func init() {
	rootCmd.AddCommand(profileCmd)
	profileCmd.AddCommand(profileCreateCmd)
	profileCmd.AddCommand(profileRemoveCmd)
	profileCmd.AddCommand(profileUpdateCmd)
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileShowCmd)

	profileCreateCmd.Flags().String(ofa.FlagProfile, "", "The profile to create.")
	profileCreateCmd.Flags().String(ofa.FlagSetProfileType, "", ofa.FlagDescSetProfileType)
	profileCreateCmd.Flags().String(ofa.FlagSetUser, "", ofa.FlagDescSetUser)
	profileCreateCmd.Flags().String(ofa.FlagSetURL, "", ofa.FlagDescSetURL)

	for _, v := range ofa.IdentityProviders {
		v.ConfigurationFlags(profileCreateCmd.Flags())
	}

	// AWS

	profileCreateCmd.Flags().String(ofa.FlagSetRole, "", ofa.FlagDescSetRole)
	profileCreateCmd.Flags().Int64(ofa.FlagSetSessionTime, 0, ofa.FlagDescSetSessionTime)

	profileRemoveCmd.Flags().String(ofa.FlagProfile, "", "The profile to delete.")

	profileUpdateCmd.Flags().String(ofa.FlagProfile, "", "The profile to edit.")
	profileUpdateCmd.Flags().String(ofa.FlagSetUser, "", ofa.FlagDescSetUser)
	profileUpdateCmd.Flags().String(ofa.FlagSetURL, "", ofa.FlagDescSetURL)

	for _, v := range ofa.IdentityProviders {
		v.ConfigurationFlags(profileUpdateCmd.Flags())
	}

	// AWS

	profileUpdateCmd.Flags().String(ofa.FlagSetRole, "", ofa.FlagDescSetRole)
	profileUpdateCmd.Flags().Int64(ofa.FlagSetSessionTime, 0, ofa.FlagDescSetSessionTime)

	profileShowCmd.Flags().String(ofa.FlagProfile, "", "The profile to show.")

}

var (
	profileCmd = &cobra.Command{
		Use:   "profile",
		Short: "Manage profiles",
		Long:  "Manage profiles.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Usage()
		},
	}

	profileCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Create new profile",
		Long:  "Create a new AWS profile.",
		Run: func(cmd *cobra.Command, args []string) {
			profile, err := ofa.NewProfileName(cmd.Flags())
			if err != nil {
				log.Fatalf("Could not create new profile: %v", err)
			}

			ofa.Information("*** Creating new profile %s", *profile.ProfileName)

			p, err := ofa.CreateProfileSettings(cmd.Flags(), profile.ProfileName, *profile)
			if err != nil {
				log.Fatalf("Could not create profile '%s': %v", *profile.ProfileName, err)
			}

			if err := ofa.StoreProfileSettings(p); err != nil {
				log.Fatalf("Could not store profile '%s': %v", *profile.ProfileName, err)
			}

		},
	}

	profileRemoveCmd = &cobra.Command{
		Use:   "remove",
		Short: "Remove profile",
		Long:  "Remove an existing AWS profile.",
		Run: func(cmd *cobra.Command, args []string) {

			profile := ofa.SelectProfile(cmd.Flags())
			if profile == nil || profile.ProfileName == nil {
				log.Fatal("Could not select profile")
			} else {

				ofa.Information("*** Deleting profile '%s'", *profile.ProfileName)

				if err := ofa.DeleteProfileSettings(*profile.ProfileName); err != nil {
					log.Fatalf("Could not delete profile '%s': %v", *profile.ProfileName, err)
				}
			}
		},
	}

	profileUpdateCmd = &cobra.Command{
		Use:   "update",
		Short: "Update profile",
		Long:  "Update an existing AWS profile.",
		Run: func(cmd *cobra.Command, args []string) {

			profile := ofa.SelectProfile(cmd.Flags())

			if profile == nil || profile.ProfileName == nil {
				// could not select the profile. Try creation
				profileCreateCmd.Run(cmd, args)
			} else {

				ofa.Information("*** Editing profile '%s'", *profile.ProfileName)

				p, err := ofa.CreateProfileSettings(cmd.Flags(), profile.ProfileName, *profile)
				if err != nil {
					log.Fatalf("Could not create global settings: %v", err)
				}

				if err := ofa.StoreProfileSettings(p); err != nil {
					log.Fatalf("Could not store profile '%s': %v", *profile.ProfileName, err)
				}
			}
		},
	}

	profileListCmd = &cobra.Command{
		Use:   "list",
		Short: "List profiles",
		Long:  "List existing AWS profiles.",
		Run: func(cmd *cobra.Command, args []string) {

			_, p := ofa.ListProfiles()

			profileNames := make([]string, 0, len(p))
			for k := range p {
				profileNames = append(profileNames, k)
			}

			fmt.Printf("**** Available profiles: %s\n", strings.Join(profileNames, ", "))
		},
	}

	profileShowCmd = &cobra.Command{
		Use:   "show",
		Short: "show profiles",
		Long:  "Show profile settings.",
		Run: func(cmd *cobra.Command, args []string) {

			ofa.ForceBatch()

			profile := ofa.SelectProfile(cmd.Flags())

			_, p := ofa.ListProfiles()

			for _, v := range p {
				if profile == nil || *v.ProfileName == *profile.ProfileName {
					v.Display(v.ProfileName)
				}
			}
		},
	}
)

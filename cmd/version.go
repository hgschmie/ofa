package cmd

import (
    "os"

    log "github.com/sirupsen/logrus"
    "github.com/spf13/cobra"
)

var (
    BuildVersion = "dev"
    BuildCommit = "none"
    BuildDate = "unknown"
    BuiltBy   = "unknown"
)

func init() {
    rootCmd.AddCommand(versionCmd)
}

var (
    versionCmd = &cobra.Command{
        Use:   "version",
        Short: "Display tool version",
        Long:  "Display tool version.",
        Run: func(cmd *cobra.Command, args []string) {
            log.Infof("ofa %s, commit %s, built at %s by %s", BuildVersion, BuildCommit, BuildDate, BuiltBy)
            os.Exit(0)
        },
    }
)

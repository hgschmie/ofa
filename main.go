package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/hgschmie/ofa/v3/cmd"
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp:          true,
		DisableQuote:              true,
		EnvironmentOverrideColors: true,
		DisableLevelTruncation:    true,
	})

}

func main() {
	// ensure that no old credential is picked up.
	_ = os.Setenv("AWS_SDK_LOAD_CONFIG", "0")

	cmd.Execute()

}

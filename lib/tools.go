package ofa

import (
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func Information(format string, args ...interface{}) {
	if *globalVerbose {
		log.Infof(format, args...)
	}
}

func toSP(s string) *string {
	return &s
}

func toIP(s int) *int64 {
	i := int64(s)
	return &i
}

func toBP(b bool) *bool {
	return &b
}

func toSPError(s string, err error) *string {
	if err != nil {
		return nil
	}
	return &s
}

func toIPError(n int64, err error) *int64 {
	if err != nil {
		return nil
	}
	return &n
}

func toBPError(b bool, err error) *bool {
	if err != nil {
		return nil
	}
	return &b
}

func extractStringP(values map[string]interface{}, key string) (*string, error) {

	if value, ok := values[key]; !ok {
		return nil, nil
	} else {
		if stringValue, ok := value.(string); ok {
			return toSP(stringValue), nil
		} else {
			return nil, fmt.Errorf("Could not extract '%v' field (%v)", key, values[key])
		}
	}
}

func getURL(s *string) (*url.URL, error) {
	if s == nil {
		return nil, nil
	}
	return url.ParseRequestURI(*s)
}

func padLabel(label string) string {
	return fmt.Sprintf("%-40s", label+":")
}

func userHomeDir() (*string, error) {

	var home *string
	if runtime.GOOS == "windows" { // Windows
		home = toSP(os.Getenv("USERPROFILE"))
	} else {
		// *nix
		home = toSP(os.Getenv("HOME"))
	}

	if home == nil || len(*home) == 0 {
		return nil, fmt.Errorf("Could not determine home directory!")
	}

	return home, nil
}

func storeFile(filename string, writeFile func(string) error) error {
	newFilename := filename + ".OFA"
	oldFilename := filename + ".OLD"

	if err := os.Remove(newFilename); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}

	if err := writeFile(newFilename); err != nil {
		return err
	}

	if _, err := os.Stat(newFilename); err == nil {
		if err := os.Rename(filename, oldFilename); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		}
		if err := os.Rename(newFilename, filename); err != nil {
			return err
		}
	}

	return nil
}

func isTTY(file *os.File) bool {
	fi, _ := file.Stat()
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func validateNumber(input string) error {
	if len(input) == 0 {
		return nil
	}
	_, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return fmt.Errorf("Invalid number: %v", input)
	}
	return nil
}

func validateBool(input string) error {
	if len(input) == 0 {
		return nil
	}
	_, err := strconv.ParseBool(input)
	if err != nil {
		return fmt.Errorf("Invalid bool: %v", input)
	}
	return nil
}

func validateURL(input string) error {
	if len(input) == 0 {
		return nil
	}
	_, err := url.ParseRequestURI(input)
	if err != nil {
		return fmt.Errorf("Could not format '%v' as a URL", input)
	}
	return nil
}

func logStringSetting(label string, value *string) {
	if *globalVerbose {
		if value == nil {
			log.Infof("%s <unset>", padLabel(label))
		} else {
			log.Infof("%s %s", padLabel(label), *value)
		}
	}
}

func logBoolSetting(label string, value *bool) {
	if *globalVerbose {
		if value == nil {
			log.Infof("%s <unset>", padLabel(label))
		} else {
			log.Infof("%s %t", padLabel(label), *value)
		}
	}
}

func logIntSetting(label string, value *int64) {
	if *globalVerbose {
		if value == nil {
			log.Infof("%s <unset>", padLabel(label))
		} else {
			log.Infof("%s %d", padLabel(label), *value)
		}
	}
}

func profileMenu(allowNone bool) configField {
	_, p := ListProfiles()

	if len(p) == 0 {
		return newNullConfig()("")
	}

	profileMap := make(map[string]*string, len(p))
	for k := range p {
		profileMap[k] = toSP(k)
	}
	if allowNone {
		profileMap["<none>"] = nil
	}
	return interactiveMenu("Profile", profileMap, nil)
}

package ofa

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	homeDir     *string
	configStore *OfaStore
	stateCache  *OfaStore
)

func init() {
	var err error
	homeDir, err = userHomeDir()
	if err != nil {
		log.Panicf("Could not determine home directory: %v", err)
	}

	configStore = newConfigStore()
	stateCache = newStateCache()
}

//
// LoadConfig loads the on-disk configuration files
//
func LoadConfig() error {
	if err := configStore.store.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}

	if err := stateCache.store.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}
	return nil
}

type OfaStore struct {
	store *viper.Viper
	file  string
}

func newConfigStore() *OfaStore {
	configStore := new(OfaStore)
	configStore.store = viper.New()
	configStore.store.SetConfigName("ofa.config")
	configStore.store.SetConfigType("toml")

	path := filepath.Join(*homeDir, ".config")

	// there is some risk here by setting XDG_CONFIG_HOME to "/root/.config" and then run this
	// program with a suid bit which would allow reading credentials of the root user
	// but then again, if you store credentials as root and allow users on a system that
	// has a root user with credentials *and* add a suid bit to this binary, then you probably
	// deserve what is coming.
	xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
	if len(xdgConfigHome) > 0 {
		path = xdgConfigHome
	}

	configStore.store.AddConfigPath(path)
	configStore.file = filepath.Join(path, "ofa.config")

	return configStore
}

func newStateCache() *OfaStore {
	stateCache := new(OfaStore)
	stateCache.store = viper.New()
	stateCache.store.SetConfigName("ofa.state")
	stateCache.store.SetConfigType("toml")

	path := filepath.Join(*homeDir, ".cache")

	xdgConfigHome := os.Getenv("XDG_STATE_HOME")
	if len(xdgConfigHome) > 0 {
		path = xdgConfigHome
	}

	stateCache.store.AddConfigPath(path)
	stateCache.file = filepath.Join(path, "ofa.state")

	return stateCache
}

func (ofaStore *OfaStore) defaultConfigProvider() ConfigProvider {
	if *globalNoConfig {
		return newNullConfig()
	}

	return func(field string) configField {
		return &StoreConfigProvider{ofaStore.store, field, "global config"}
	}
}

func (ofaStore *OfaStore) subStore(field string) *viper.Viper {
	store := ofaStore.store.Sub(field)
	if store == nil {
		// no such key exists
		store = viper.New()
	}

	return store
}

func (ofaStore *OfaStore) loadConfigFile() (*toml.Tree, error) {
	tree, err := toml.LoadFile(ofaStore.file)
	if err != nil {
		if os.IsNotExist(err) {
			return toml.Load("")
		}
		return nil, err
	}
	return tree, nil
}

func (ofaStore *OfaStore) storeConfigFile(tree *toml.Tree) error {
	return storeFile(ofaStore.file, func(filename string) error {
		if file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666); err != nil {
			return err
		} else {
			defer file.Close()
			if _, err := tree.WriteTo(file); err != nil {
				return err
			}
		}
		return nil
	})
}

type StoreConfigProvider struct {
	store      *viper.Viper
	field      string
	configName string
}

func (p *StoreConfigProvider) location() string {
	return fmt.Sprintf("%s, key: '%s'", p.configName, p.field)
}

func (p *StoreConfigProvider) stringValue() (*string, string) {
	if p.store.IsSet(p.field) {
		return toSP(p.store.GetString(p.field)), p.location()
	}
	return nil, ""
}

func (p *StoreConfigProvider) intValue() (*int64, string) {
	if p.store.IsSet(p.field) {
		return toIPError(p.store.GetInt64(p.field), nil), p.location()
	}
	return nil, ""
}

func (p *StoreConfigProvider) boolValue() (*bool, string) {
	if p.store.IsSet(p.field) {
		return toBPError(p.store.GetBool(p.field), nil), p.location()
	}
	return nil, ""
}

func getString(store *viper.Viper, field string) *string {
	if store.IsSet(field) {
		return toSP(store.GetString(field))
	}
	return nil
}

func getInt(store *viper.Viper, field string) *int64 {
	if store.IsSet(field) {
		v := store.GetInt64(field)
		return &v
	}
	return nil
}

func getBool(store *viper.Viper, field string) *bool {
	if store.IsSet(field) {
		v := store.GetBool(field)
		return &v
	}
	return nil
}

func setString(tree *toml.Tree, field string, value *string) error {
	if value == nil {
		if tree.Has(field) {
			return tree.Delete(field)
		}
	} else {
		tree.Set(field, *value)
	}

	return nil
}

func setInt(tree *toml.Tree, field string, value *int64) error {
	if value == nil {
		if tree.Has(field) {
			return tree.Delete(field)
		}
	} else {
		tree.Set(field, *value)
	}

	return nil
}

func setBool(tree *toml.Tree, field string, value *bool) error {
	if value == nil {
		if tree.Has(field) {
			return tree.Delete(field)
		}
	} else {
		tree.Set(field, *value)
	}

	return nil
}

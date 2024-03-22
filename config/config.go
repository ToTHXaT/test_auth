package config

import (
	"github.com/pelletier/go-toml"
	"io"
	"log"
	"os"
)

type TomlConfig struct {
	MongoDBURI                 string `toml:"mongodb_uri"`
	AccessTokenLifetimeMinutes int    `toml:"access_token_lifetime_minutes"`
	RefreshTokenLifetimeDays   int    `toml:"refresh_token_lifetime_days"`
	SecretKey                  string `toml:"secret_key"`
}

var Config *TomlConfig

func LoadConfig() {
	if Config == nil {
		file, err := os.Open("config.toml")
		if err != nil {
			log.Fatal(err)
		}

		data, err := io.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}

		Config = &TomlConfig{}
		err = toml.Unmarshal(data, Config)
		if err != nil {
			log.Fatal(err)
		}
	}
}

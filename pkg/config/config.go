package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// Auth0設定
	Auth0 Auth0Config
	// サーバー設定
	Server ServerConfig
}

type Auth0Config struct {
	Domain       string `envconfig:"AUTH0_DOMAIN" required:"true"`
	ClientID     string `envconfig:"AUTH0_CLIENT_ID" required:"true"`
	ClientSecret string `envconfig:"AUTH0_CLIENT_SECRET" required:"true"`
	RedirectURL  string `envconfig:"AUTH0_REDIRECT_URL" required:"true"`
}

type ServerConfig struct {
	Port            int `envconfig:"SERVER_PORT" default:"50051"`
	ShutdownTimeout int `envconfig:"SERVER_SHUTDOWN_TIMEOUT" default:"10"` // seconds
}

func LoadConfig(files ...string) (*Config, error) {
	if os.Getenv("APP_ENV") == "test" {
		files = append(files, "../../.env.test") // Load .env.test for the test environment
	}
	for _, file := range files {
		if err := godotenv.Load(file); err != nil {
			continue
		}
	}

	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}
	return &cfg, nil
}

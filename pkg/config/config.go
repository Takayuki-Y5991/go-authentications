package config

type Config struct {
	Domain       string `envconfig: "AUTH0_DOMAIN" required:"true"`
	ClientID     string `envconfig: "AUTH0_CLIENT_ID" required:"true"`
	ClientSecret string `envconfig: "AUTH0_CLIENT_SECRET" required:"true"`
	Audience     string `envconfig: "AUTH0_AUDIENCE" required:"true"`
	RedirectURL  string `envconfig: "AUTH0_REDIRECT_URL" required:"true"`
}

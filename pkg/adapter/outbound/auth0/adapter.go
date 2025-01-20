package auth0

import (
	"net/http"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type Auth0Provider struct {
	oauth2Config *oauth2.Config
	domain       string
	audience     string
	httpClient   *http.Client
	logger       *zap.Logger
}

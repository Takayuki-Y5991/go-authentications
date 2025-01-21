package auth0

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Takayuki-Y5991/go-authentications/pkg/config"
	"github.com/Takayuki-Y5991/go-authentications/pkg/domain/model"
	"github.com/Takayuki-Y5991/go-authentications/pkg/port/outbound"
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

func NewAuth0Adapter(config *config.Config, logger *zap.Logger) (outbound.AuthPort, error) {
	oauth2Config := &oauth2.Config{
		ClientID:     config.Auth0.ClientID,
		ClientSecret: config.Auth0.ClientSecret,
		RedirectURL:  config.Auth0.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s/authorize", config.Auth0.Domain),
			TokenURL: fmt.Sprintf("https://%s/oauth/token", config.Auth0.Domain),
		},
		Scopes: []string{"openid", "profile", "email", "offline_access"},
	}
	return &Auth0Provider{
		oauth2Config: oauth2Config,
		domain:       config.Auth0.Domain,
		audience:     config.Auth0.Audience,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		logger:       logger,
	}, nil
}

// Auth0Providerに必要なメソッドを実装
func (a *Auth0Provider) GenerateAuthorizationURL(ctx context.Context, provider model.IdentityProvider, status string, opts *model.AuthorizationOptions) (string, error) {
	tmpConfig := *a.oauth2Config
	if len(opts.Scope) > 0 {
		tmpConfig.Scopes = append(tmpConfig.Scopes, opts.Scope...)
	}
	if opts.RedirectURI != "" {
		tmpConfig.RedirectURL = opts.RedirectURI
	}

	authOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("audience", a.audience),
	}
	if opts.CodeChallenge != "" {
		authOpts = append(authOpts,
			oauth2.SetAuthURLParam("code_challenge", opts.CodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", opts.CodeChallengeMethod),
		)
	}

	switch provider {
	case model.IdentityProviderGoogle:
		authOpts = append(authOpts, oauth2.SetAuthURLParam("connection", "google-oauth2"))
	case model.IdentityProviderGithub:
		authOpts = append(authOpts, oauth2.SetAuthURLParam("connection", "github"))
	default:
		return "", fmt.Errorf("Unsupported identity provider: %v", provider)
	}
	for k, v := range opts.Extra {
		authOpts = append(authOpts, oauth2.SetAuthURLParam(k, v))
	}

	return tmpConfig.AuthCodeURL(status, authOpts...), nil
}

func (a *Auth0Provider) ExchangeAuthorizationCode(ctx context.Context, code, redirectURI, codeVerifier string, provider model.IdentityProvider) (*model.TokenInfo, error) {
	tmpConfig := *a.oauth2Config
	if redirectURI != "" {
		tmpConfig.RedirectURL = redirectURI
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("audience", a.audience),
	}

	if codeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}

	token, err := tmpConfig.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	var scope []string
	if s := token.Extra("scope"); s != nil {
		if str, ok := s.(string); ok {
			scope = strings.Split(str, " ")
		}
	}
	return &model.TokenInfo{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int64(time.Until(token.Expiry).Seconds()),
		TokenType:    token.TokenType,
		Scopes:       scope,
		IDToken:      token.Extra("id_token").(string),
		MFAStatus:    model.MFAStatusDisabled,
		IssuedAt:     time.Now(),
	}, nil
}

func (a *Auth0Provider) VerifyToken(ctx context.Context, token string) (*model.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/userinfo", a.domain), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create response: %w", err)
	}
	req.Header.Set("Authentication", "Bearer "+token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &model.VerificationResult{
			IsValid: false,
		}, nil
	}

	return &model.VerificationResult{
		IsValid:      true,
		MFACompleted: true, // 現状MFAをSkip
		ExpiresAt:    time.Now().Add(time.Hour),
	}, nil
}

func (a *Auth0Provider) RefreshToken(ctx context.Context, refreshToken string) (*model.TokenInfo, error) {
	token, err := a.oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	}).Token()

	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return &model.TokenInfo{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int64(time.Until(token.Expiry).Seconds()),
		TokenType:    token.TokenType,
		MFAStatus:    model.MFAStatusDisabled,
		IssuedAt:     time.Now(),
	}, nil
}

func (a *Auth0Provider) GetUserInfo(ctx context.Context, accessToken string) (*model.UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/userinfo", a.domain), nil)
	if err != nil {
		return nil, fmt.Errorf("failed create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status: %d", resp.StatusCode)
	}
	var userinfo struct {
		Sub           string                 `json:"sub"`
		Email         string                 `json:"email"`
		EmailVerified bool                   `json:"email_verified"`
		Name          string                 `json:"name"`
		Picture       string                 `json:"picture"`
		Roles         []string               `json:"https://your-namespace/roles"`
		Metadata      map[string]interface{} `json:"user_metadata"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&userinfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &model.UserInfo{
		ID:            userinfo.Sub,
		Email:         userinfo.Email,
		EmailVerified: userinfo.EmailVerified,
		Name:          userinfo.Name,
		Roles:         userinfo.Roles,
		MFAInfo: &model.MFAInfo{
			Status: model.MFAStatusDisabled,
		},
		Metadata: userinfo.Metadata,
	}, nil
}

func (a *Auth0Provider) GetMFAStatus(ctx context.Context, accessToken string) (*model.MFAInfo, error) {
	return &model.MFAInfo{
		Status:         model.MFAStatusDisabled,
		EnabledMethods: []model.MFAMethod{},
	}, nil
}

func (a *Auth0Provider) CompleteMFAChallenge(ctx context.Context, accessToken, mfaToken string) (*model.TokenInfo, error) {
	return &model.TokenInfo{
		AccessToken: accessToken,
		MFAStatus:   model.MFAStatusDisabled,
		IssuedAt:    time.Now(),
	}, nil
}

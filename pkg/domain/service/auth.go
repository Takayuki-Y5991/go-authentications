package service

import (
	"context"
	"fmt"

	"github.com/Takayuki-Y5991/go-authentications/pkg/domain/model"
	"github.com/Takayuki-Y5991/go-authentications/pkg/port/outbound"
	"go.uber.org/zap"
)

type AuthenticationService struct {
	authProvider outbound.AuthPort
	logger       *zap.Logger
}

func NewAuthenticationService(authProvider outbound.AuthPort, logger *zap.Logger) *AuthenticationService {
	return &AuthenticationService{
		authProvider: authProvider,
		logger:       logger,
	}
}

func (s *AuthenticationService) GenerateAuthorizationURL(ctx context.Context, provider model.IdentityProvider, status string, opts *model.AuthorizationOptions) (string, error) {

	if err := validateAuthorizationOptions(opts); err != nil {
		s.logger.Error("Invalid authorization options", zap.Error(err))
		return "", fmt.Errorf("invalid authorization options: %w", err)
	}

	url, err := s.authProvider.GenerateAuthorizationURL(ctx, provider, status, opts)
	if err != nil {
		s.logger.Error("Failed to generate authorization URL", zap.Error(err))
		return "", fmt.Errorf("failed to generate authorization URL: %w", err)
	}

	return url, nil
}

func (s *AuthenticationService) ExchangeAuthorizationCode(ctx context.Context, code, redirectURI, codeVerifier string, provider model.IdentityProvider) (*model.TokenInfo, error) {

	if code == "" {
		return nil, fmt.Errorf("authorization code is required")
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("redirect URI is required")
	}

	tokenInfo, err := s.authProvider.ExchangeAuthorizationCode(ctx, code, redirectURI, codeVerifier, provider)
	if err != nil {
		s.logger.Error("Failed to exchange authorization code", zap.Error(err))
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	if err := validateTokenInfo(tokenInfo); err != nil {
		s.logger.Error("Invalid token info", zap.Error(err))
		return nil, fmt.Errorf("invalid token info: %w", err)
	}

	return tokenInfo, nil
}

func (s *AuthenticationService) VerifyToken(ctx context.Context, token string) (*model.VerificationResult, error) {
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}
	result, err := s.authProvider.VerifyToken(ctx, token)
	if err != nil {
		s.logger.Error("Failed to verify token", zap.Error(err))
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}
	return result, nil
}

func (s *AuthenticationService) RefreshToken(ctx context.Context, refreshToken string) (*model.TokenInfo, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}
	tokenInfo, err := s.authProvider.RefreshToken(ctx, refreshToken)
	if err != nil {
		s.logger.Error("Failed to refresh token", zap.Error(err))
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	return tokenInfo, nil
}

func (s *AuthenticationService) GetUserInfo(ctx context.Context, accessToken string) (*model.UserInfo, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("access token is required")
	}
	userInfo, err := s.authProvider.GetUserInfo(ctx, accessToken)
	if err != nil {
		s.logger.Error("Failed to get user info", zap.Error(err))
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	return userInfo, nil
}

func (s *AuthenticationService) GetMFAStatus(ctx context.Context, accessToken string) (*model.MFAInfo, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("access token is required")
	}
	mfaInfo, err := s.authProvider.GetMFAStatus(ctx, accessToken)
	if err != nil {
		s.logger.Error("Failed to get MFA status", zap.Error(err))
		return nil, fmt.Errorf("failed to get MFA status: %w", err)
	}
	return mfaInfo, nil
}

func (s *AuthenticationService) CompleteMFAChallenge(ctx context.Context, accessToken, mfaToken string) (*model.TokenInfo, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("access token is required")
	}
	if mfaToken == "" {
		return nil, fmt.Errorf("MFA token is required")
	}
	tokenInfo, err := s.authProvider.CompleteMFAChallenge(ctx, accessToken, mfaToken)
	if err != nil {
		s.logger.Error("Failed to complete MFA challenge", zap.Error(err))
		return nil, fmt.Errorf("failed to complete MFA challenge: %w", err)
	}
	return tokenInfo, nil
}

func validateAuthorizationOptions(opts *model.AuthorizationOptions) error {
	if opts == nil {
		return fmt.Errorf("authorization options is required")
	}
	if opts.RedirectURI == "" {
		return fmt.Errorf("redirect URI is required")
	}
	if opts.CodeChallenge != "" && opts.CodeChallengeMethod == "" {
		return fmt.Errorf("code challenge method is required when code challenge is provided")
	}
	return nil
}

func validateTokenInfo(tokenInfo *model.TokenInfo) error {
	if tokenInfo == nil {
		return fmt.Errorf("token info is required")
	}
	if tokenInfo.AccessToken == "" {
		return fmt.Errorf("access token is required")
	}
	if tokenInfo.TokenType == "" {
		return fmt.Errorf("expires in is required")
	}
	return nil
}

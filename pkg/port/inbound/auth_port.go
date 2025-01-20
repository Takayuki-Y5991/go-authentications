package inbound

import (
	"context"

	"github.com/Takayuki-Y5991/go-authentications/pkg/domain/model"
)

type AuthPort interface {
	GenerateAuthorizationURL(ctx context.Context, provider model.IdentityProvider, status string, opts *model.AuthorizationOptions) (string, error)

	// Change authorizationCode and token
	ExchangeAuthorizationCode(ctx context.Context, code, redirectURI, codeVerifier string, provider model.IdentityProvider) (*model.TokenInfo, error)

	// Verify token
	VerifyToken(ctx context.Context, token string) (*model.VerificationResult, error)

	RefreshToken(ctx context.Context, refreshToken string) (*model.TokenInfo, error)

	GetUserInfo(ctx context.Context, accessToken string) (*model.UserInfo, error)

	GetMFAStatus(ctx context.Context, accessToken string) (*model.MFAInfo, error)

	CompleteMFAChallenge(ctx context.Context, accessToken, mfaToken string) (*model.TokenInfo, error)
}

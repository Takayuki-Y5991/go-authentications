package mock

import (
	"context"

	"github.com/Takayuki-Y5991/go-authentications/pkg/domain/model"
	"github.com/stretchr/testify/mock"
)

type MockAuthPort struct {
	mock.Mock
}

func (m *MockAuthPort) GenerateAuthorizationURL(ctx context.Context, provider model.IdentityProvider, status string, opts *model.AuthorizationOptions) (string, error) {
	args := m.Called(ctx, provider, status, opts)
	return args.String(0), args.Error(1)
}

func (m *MockAuthPort) ExchangeAuthorizationCode(ctx context.Context, code, redirectURI, codeVerifier string, provider model.IdentityProvider) (*model.TokenInfo, error) {
	args := m.Called(ctx, code, redirectURI, codeVerifier, provider)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.TokenInfo), args.Error(1)
}

func (m *MockAuthPort) VerifyToken(ctx context.Context, token string) (*model.VerificationResult, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.VerificationResult), args.Error(1)
}

func (m *MockAuthPort) RefreshToken(ctx context.Context, refreshToken string) (*model.TokenInfo, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.TokenInfo), args.Error(1)
}

func (m *MockAuthPort) GetUserInfo(ctx context.Context, accessToken string) (*model.UserInfo, error) {
	args := m.Called(ctx, accessToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserInfo), args.Error(1)
}

func (m *MockAuthPort) GetMFAStatus(ctx context.Context, accessToken string) (*model.MFAInfo, error) {
	args := m.Called(ctx, accessToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.MFAInfo), args.Error(1)
}

func (m *MockAuthPort) CompleteMFAChallenge(ctx context.Context, accessToken, mfaToken string) (*model.TokenInfo, error) {
	args := m.Called(ctx, accessToken, mfaToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.TokenInfo), args.Error(1)
}

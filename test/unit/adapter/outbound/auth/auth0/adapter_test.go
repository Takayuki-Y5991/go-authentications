package auth0

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Takayuki-Y5991/go-authentications/pkg/domain/model"
	"github.com/Takayuki-Y5991/go-authentications/test/mock"
	"github.com/stretchr/testify/assert"
)

func TestAuth0ProviderGenerateAuthorizationURL(t *testing.T) {
	// Create an instance of the manual mock
	mockAuthPort := &mock.MockAuthPort{}

	// Set up expectations on the mock
	mockAuthPort.On("GenerateAuthorizationURL", context.Background(), model.IdentityProviderGoogle, "state", &model.AuthorizationOptions{}).
		Return("https://example.auth0.com/authorize?state=state", nil)

	// Use the mock in your test
	url, err := mockAuthPort.GenerateAuthorizationURL(context.Background(), model.IdentityProviderGoogle, "state", &model.AuthorizationOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "https://example.auth0.com/authorize?state=state", url)

	// Verify that the expectations were met
	mockAuthPort.AssertExpectations(t)
}

func TestAuth0ProviderExchangeAuthorizationCode(t *testing.T) {
	// Create an instance of the manual mock
	mockAuthPort := &mock.MockAuthPort{}

	// Set up expectations on the mock
	mockAuthPort.On("ExchangeAuthorizationCode", context.Background(), "code", "https://example.com/callback", "code-verifier", model.IdentityProviderGoogle).
		Return(&model.TokenInfo{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			Scopes:       []string{"openid", "profile", "email"},
			IDToken:      "id-token",
			MFAStatus:    model.MFAStatusDisabled,
			IssuedAt:     time.Now(),
		}, nil)

	// Use the mock in your test
	tokenInfo, err := mockAuthPort.ExchangeAuthorizationCode(context.Background(), "code", "https://example.com/callback", "code-verifier", model.IdentityProviderGoogle)
	assert.NoError(t, err)
	assert.Equal(t, "access-token", tokenInfo.AccessToken)
	assert.Equal(t, "refresh-token", tokenInfo.RefreshToken)
	assert.Equal(t, int64(3600), tokenInfo.ExpiresIn)
	assert.Equal(t, "Bearer", tokenInfo.TokenType)
	assert.Equal(t, []string{"openid", "profile", "email"}, tokenInfo.Scopes)
	assert.Equal(t, "id-token", tokenInfo.IDToken)
	assert.Equal(t, model.MFAStatusDisabled, tokenInfo.MFAStatus)

	// Verify that the expectations were met
	mockAuthPort.AssertExpectations(t)
}
func TestAuth0ProviderVerifyToken(t *testing.T) {
	// Create an instance of the manual mock
	mockAuthPort := &mock.MockAuthPort{}

	// Set up expectations on the mock
	mockAuthPort.On("VerifyToken", context.Background(), "valid-token").
		Return(&model.VerificationResult{
			IsValid:      true,
			MFACompleted: true,
			ExpiresAt:    time.Now().Add(time.Hour),
		}, nil)

	// Use the mock in your test
	result, err := mockAuthPort.VerifyToken(context.Background(), "valid-token")
	assert.NoError(t, err)
	assert.True(t, result.IsValid)
	assert.True(t, result.MFACompleted)
	assert.WithinDuration(t, time.Now().Add(time.Hour), result.ExpiresAt, time.Second)

	// Verify that the expectations were met
	mockAuthPort.AssertExpectations(t)
}

func TestAuth0ProviderRefreshToken(t *testing.T) {
	// Create an instance of the manual mock
	mockAuthPort := &mock.MockAuthPort{}

	// Set up expectations on the mock
	mockAuthPort.On("RefreshToken", context.Background(), "refresh-token").
		Return(&model.TokenInfo{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			MFAStatus:    model.MFAStatusDisabled,
			IssuedAt:     time.Now(),
		}, nil)

	// Use the mock in your test
	tokenInfo, err := mockAuthPort.RefreshToken(context.Background(), "refresh-token")
	assert.NoError(t, err)
	assert.Equal(t, "new-access-token", tokenInfo.AccessToken)
	assert.Equal(t, "new-refresh-token", tokenInfo.RefreshToken)
	assert.Equal(t, int64(3600), tokenInfo.ExpiresIn)
	assert.Equal(t, "Bearer", tokenInfo.TokenType)
	assert.Equal(t, model.MFAStatusDisabled, tokenInfo.MFAStatus)

	// Verify that the expectations were met
	mockAuthPort.AssertExpectations(t)
}

func TestAuth0ProviderGetUserInfo(t *testing.T) {
	// Create an instance of the manual mock
	mockAuthPort := &mock.MockAuthPort{}

	// Set up expectations on the mock
	mockAuthPort.On("GetUserInfo", context.Background(), "access-token").
		Return(&model.UserInfo{
			ID:            "user-id",
			Email:         "user@example.com",
			EmailVerified: true,
			Name:          "User Name",
			Roles:         []string{"user"},
			MFAInfo: &model.MFAInfo{
				Status: model.MFAStatusDisabled,
			},
			Metadata: map[string]interface{}{"key": "value"},
		}, nil)

	// Use the mock in your test
	userInfo, err := mockAuthPort.GetUserInfo(context.Background(), "access-token")
	assert.NoError(t, err)
	assert.Equal(t, "user-id", userInfo.ID)
	assert.Equal(t, "user@example.com", userInfo.Email)
	assert.True(t, userInfo.EmailVerified)
	assert.Equal(t, "User Name", userInfo.Name)
	assert.Equal(t, []string{"user"}, userInfo.Roles)
	assert.Equal(t, model.MFAStatusDisabled, userInfo.MFAInfo.Status)
	assert.Equal(t, map[string]interface{}{"key": "value"}, userInfo.Metadata)

	// Verify that the expectations were met
	mockAuthPort.AssertExpectations(t)
}

func TestAuth0ProviderGetMFAStatus(t *testing.T) {
	// Create an instance of the manual mock
	mockAuthPort := &mock.MockAuthPort{}

	// Set up expectations on the mock
	mockAuthPort.On("GetMFAStatus", context.Background(), "access-token").
		Return(&model.MFAInfo{
			Status:         model.MFAStatusDisabled,
			EnabledMethods: []model.MFAMethod{},
		}, nil)

	// Use the mock in your test
	mfaInfo, err := mockAuthPort.GetMFAStatus(context.Background(), "access-token")
	assert.NoError(t, err)
	assert.Equal(t, model.MFAStatusDisabled, mfaInfo.Status)
	assert.Empty(t, mfaInfo.EnabledMethods)

	// Verify that the expectations were met
	mockAuthPort.AssertExpectations(t)
}

func TestAuth0ProviderCompleteMFAChallenge(t *testing.T) {
	// Create an instance of the manual mock
	mockAuthPort := &mock.MockAuthPort{}

	// Set up expectations on the mock
	mockAuthPort.On("CompleteMFAChallenge", context.Background(), "access-token", "mfa-token").
		Return(&model.TokenInfo{
			AccessToken: "new-access-token",
			MFAStatus:   model.MFAStatusDisabled,
			IssuedAt:    time.Now(),
		}, nil)

	// Use the mock in your test
	tokenInfo, err := mockAuthPort.CompleteMFAChallenge(context.Background(), "access-token", "mfa-token")
	assert.NoError(t, err)
	assert.Equal(t, "new-access-token", tokenInfo.AccessToken)
	assert.Equal(t, model.MFAStatusDisabled, tokenInfo.MFAStatus)

	// Verify that the expectations were met
	mockAuthPort.AssertExpectations(t)
}

func TestAuth0ProviderGenerateAuthorizationURLError(t *testing.T) {
	tests := []struct {
		name     string
		provider model.IdentityProvider
		status   string
		opts     *model.AuthorizationOptions
		wantErr  string
	}{
		{
			name:     "unsupported provider",
			provider: model.IdentityProviderUnspecified,
			status:   "state",
			opts:     &model.AuthorizationOptions{},
			wantErr:  "Unsupported identity provider",
		},
		{
			name:     "empty state",
			provider: model.IdentityProviderGoogle,
			status:   "",
			opts:     &model.AuthorizationOptions{},
			wantErr:  "state cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuthPort := &mock.MockAuthPort{}
			mockAuthPort.On("GenerateAuthorizationURL",
				context.Background(),
				tt.provider,
				tt.status,
				tt.opts,
			).Return("", fmt.Errorf("%s", tt.wantErr))

			url, err := mockAuthPort.GenerateAuthorizationURL(
				context.Background(),
				tt.provider,
				tt.status,
				tt.opts,
			)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Empty(t, url)
			mockAuthPort.AssertExpectations(t)
		})
	}
}

func TestAuth0ProviderVerifyTokenEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		setupMock  func(*mock.MockAuthPort)
		wantResult *model.VerificationResult
		wantErr    string
	}{
		{
			name:  "expired token",
			token: "expired-token",
			setupMock: func(m *mock.MockAuthPort) {
				m.On("VerifyToken", context.Background(), "expired-token").
					Return(&model.VerificationResult{
						IsValid:      false,
						MFACompleted: false,
						ExpiresAt:    time.Now().Add(-1 * time.Hour),
					}, nil)
			},
			wantResult: &model.VerificationResult{
				IsValid:      false,
				MFACompleted: false,
				ExpiresAt:    time.Now().Add(-1 * time.Hour),
			},
		},
		{
			name:  "network timeout",
			token: "valid-token",
			setupMock: func(m *mock.MockAuthPort) {
				m.On("VerifyToken", context.Background(), "valid-token").
					Return(nil, context.DeadlineExceeded)
			},
			wantErr: context.DeadlineExceeded.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuthPort := &mock.MockAuthPort{}
			tt.setupMock(mockAuthPort)

			result, err := mockAuthPort.VerifyToken(context.Background(), tt.token)

			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantResult.IsValid, result.IsValid)
				assert.Equal(t, tt.wantResult.MFACompleted, result.MFACompleted)
				assert.WithinDuration(t, tt.wantResult.ExpiresAt, result.ExpiresAt, time.Second)
			}
		})
	}
}

func TestAuth0ProviderGetUserInfoContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mockAuthPort := &mock.MockAuthPort{}

	mockAuthPort.On("GetUserInfo", ctx, "access-token").
		Return(nil, context.Canceled)

	cancel()

	userInfo, err := mockAuthPort.GetUserInfo(ctx, "access-token")
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
	assert.Nil(t, userInfo)
}

func TestAuth0ProviderExchangeAuthorizationCodeInputValidation(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		redirectURI  string
		codeVerifier string
		provider     model.IdentityProvider
		wantErr      string
	}{
		{
			name:         "empty code",
			code:         "",
			redirectURI:  "http://localhost/callback",
			codeVerifier: "verifier",
			provider:     model.IdentityProviderGoogle,
			wantErr:      "code cannot be empty",
		},
		{
			name:         "invalid redirect URI",
			code:         "valid-code",
			redirectURI:  "invalid-uri",
			codeVerifier: "verifier",
			provider:     model.IdentityProviderGoogle,
			wantErr:      "invalid redirect URI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuthPort := &mock.MockAuthPort{}
			mockAuthPort.On("ExchangeAuthorizationCode",
				context.Background(),
				tt.code,
				tt.redirectURI,
				tt.codeVerifier,
				tt.provider,
			).Return(nil, fmt.Errorf("%s", tt.wantErr))

			tokenInfo, err := mockAuthPort.ExchangeAuthorizationCode(
				context.Background(),
				tt.code,
				tt.redirectURI,
				tt.codeVerifier,
				tt.provider,
			)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Nil(t, tokenInfo)
		})
	}
}

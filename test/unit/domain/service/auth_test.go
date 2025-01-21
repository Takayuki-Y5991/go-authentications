package service_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Takayuki-Y5991/go-authentications/pkg/domain/model"
	"github.com/Takayuki-Y5991/go-authentications/pkg/domain/service"
	TM "github.com/Takayuki-Y5991/go-authentications/test/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func setupTest(t *testing.T) (*service.AuthenticationService, *TM.MockAuthPort) {
	logger, _ := zap.NewDevelopment()
	mockAuth := new(TM.MockAuthPort)
	svc := service.NewAuthenticationService(mockAuth, logger)
	return svc, mockAuth
}

func TestGenerateAuthorizationURL(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		expectedURL := "https://example.com/auth"
		opts := &model.AuthorizationOptions{
			RedirectURI: "https://example.com/callback",
		}
		mockAuth.On("GenerateAuthorizationURL", mock.Anything, model.IdentityProviderGoogle, "state", opts).Return(expectedURL, nil)

		url, err := svc.GenerateAuthorizationURL(context.Background(), model.IdentityProviderGoogle, "state", opts)

		assert.NoError(t, err)
		assert.Equal(t, expectedURL, url)
		mockAuth.AssertExpectations(t)
	})

	t.Run("failure_invalid_options", func(t *testing.T) {
		svc, _ := setupTest(t)
		opts := &model.AuthorizationOptions{}

		_, err := svc.GenerateAuthorizationURL(context.Background(), model.IdentityProviderGoogle, "state", opts)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid authorization options")
	})

	t.Run("failure_provider_error", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		opts := &model.AuthorizationOptions{
			RedirectURI: "https://example.com/callback",
		}
		mockAuth.On("GenerateAuthorizationURL", mock.Anything, model.IdentityProviderGoogle, "state", opts).Return("", errors.New("provider error"))

		_, err := svc.GenerateAuthorizationURL(context.Background(), model.IdentityProviderGoogle, "state", opts)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate authorization URL")
		mockAuth.AssertExpectations(t)
	})

	t.Run("success_with_full_options", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		opts := &model.AuthorizationOptions{
			RedirectURI:         "https://example.com/callback",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
			Scope:               []string{"openid", "profile", "email"},
			Prompt:              "login",
			MaxAge:              3600,
			Nonce:               "nonce123",
			UILocales:           []string{"en", "ja"},
			IDTokenHint:         "previous_token",
			Extra:               map[string]string{"custom_param": "value"},
		}
		expectedURL := "https://example.com/auth"
		mockAuth.On("GenerateAuthorizationURL", mock.Anything, model.IdentityProviderGoogle, "state", opts).Return(expectedURL, nil)

		url, err := svc.GenerateAuthorizationURL(context.Background(), model.IdentityProviderGoogle, "state", opts)

		assert.NoError(t, err)
		assert.Equal(t, expectedURL, url)
		mockAuth.AssertExpectations(t)
	})

	t.Run("failure_nil_options", func(t *testing.T) {
		svc, _ := setupTest(t)

		_, err := svc.GenerateAuthorizationURL(context.Background(), model.IdentityProviderGoogle, "state", nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authorization options is required")
	})

	t.Run("failure_invalid_code_challenge", func(t *testing.T) {
		svc, _ := setupTest(t)
		opts := &model.AuthorizationOptions{
			RedirectURI:   "https://example.com/callback",
			CodeChallenge: "challenge",
			// CodeChallengeMethod is missing
		}

		_, err := svc.GenerateAuthorizationURL(context.Background(), model.IdentityProviderGoogle, "state", opts)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "code challenge method is required")
	})
}

func TestExchangeAuthorizationCode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		expectedTokenInfo := &model.TokenInfo{
			AccessToken:  "access_token",
			RefreshToken: "refresh_token",
			TokenType:    "bearer",
			ExpiresIn:    3600,
		}
		mockAuth.On("ExchangeAuthorizationCode", mock.Anything, "code", "https://example.com/callback", "verifier", model.IdentityProviderGoogle).Return(expectedTokenInfo, nil)

		tokenInfo, err := svc.ExchangeAuthorizationCode(context.Background(), "code", "https://example.com/callback", "verifier", model.IdentityProviderGoogle)

		assert.NoError(t, err)
		assert.Equal(t, expectedTokenInfo, tokenInfo)
		mockAuth.AssertExpectations(t)
	})

	t.Run("failure_empty_code", func(t *testing.T) {
		svc, _ := setupTest(t)

		_, err := svc.ExchangeAuthorizationCode(context.Background(), "", "https://example.com/callback", "verifier", model.IdentityProviderGoogle)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authorization code is required")
	})

	t.Run("failure_empty_redirect_uri", func(t *testing.T) {
		svc, _ := setupTest(t)

		_, err := svc.ExchangeAuthorizationCode(context.Background(), "code", "", "verifier", model.IdentityProviderGoogle)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redirect URI is required")
	})

	t.Run("failure_provider_error", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		mockAuth.On("ExchangeAuthorizationCode", mock.Anything, "code", "https://example.com/callback", "verifier", model.IdentityProviderGoogle).Return(nil, errors.New("provider error"))

		_, err := svc.ExchangeAuthorizationCode(context.Background(), "code", "https://example.com/callback", "verifier", model.IdentityProviderGoogle)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to exchange authorization code")
		mockAuth.AssertExpectations(t)
	})

	t.Run("failure_invalid_token_info", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		invalidTokenInfo := &model.TokenInfo{}
		mockAuth.On("ExchangeAuthorizationCode", mock.Anything, "code", "https://example.com/callback", "verifier", model.IdentityProviderGoogle).Return(invalidTokenInfo, nil)

		_, err := svc.ExchangeAuthorizationCode(context.Background(), "code", "https://example.com/callback", "verifier", model.IdentityProviderGoogle)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token info")
		mockAuth.AssertExpectations(t)
	})
}

func TestVerifyToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		expectedResult := &model.VerificationResult{
			IsValid:      true,
			UserID:       "user_id",
			ExpiresAt:    time.Now().Add(time.Hour),
			Scopes:       []string{"read", "write"},
			MFACompleted: true,
		}
		mockAuth.On("VerifyToken", mock.Anything, "token").Return(expectedResult, nil)

		result, err := svc.VerifyToken(context.Background(), "token")

		assert.NoError(t, err)
		assert.Equal(t, expectedResult, result)
		mockAuth.AssertExpectations(t)
	})

	t.Run("failure_empty_token", func(t *testing.T) {
		svc, _ := setupTest(t)

		_, err := svc.VerifyToken(context.Background(), "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is required")
	})

	t.Run("failure_provider_error", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		mockAuth.On("VerifyToken", mock.Anything, "token").Return(nil, errors.New("provider error"))

		_, err := svc.VerifyToken(context.Background(), "token")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to verify token")
		mockAuth.AssertExpectations(t)
	})
}

func TestRefreshToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		expectedTokenInfo := &model.TokenInfo{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			TokenType:    "bearer",
			ExpiresIn:    3600,
		}
		mockAuth.On("RefreshToken", mock.Anything, "refresh_token").Return(expectedTokenInfo, nil)

		tokenInfo, err := svc.RefreshToken(context.Background(), "refresh_token")

		assert.NoError(t, err)
		assert.Equal(t, expectedTokenInfo, tokenInfo)
		mockAuth.AssertExpectations(t)
	})

	t.Run("failure_empty_refresh_token", func(t *testing.T) {
		svc, _ := setupTest(t)

		_, err := svc.RefreshToken(context.Background(), "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token is required")
	})

	t.Run("failure_provider_error", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		mockAuth.On("RefreshToken", mock.Anything, "refresh_token").Return(nil, errors.New("provider error"))

		_, err := svc.RefreshToken(context.Background(), "refresh_token")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to refresh token")
		mockAuth.AssertExpectations(t)
	})
}

func TestGetUserInfo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		expectedUserInfo := &model.UserInfo{
			ID:    "user_id",
			Email: "test@example.com",
		}
		mockAuth.On("GetUserInfo", mock.Anything, "access_token").Return(expectedUserInfo, nil)

		userInfo, err := svc.GetUserInfo(context.Background(), "access_token")

		assert.NoError(t, err)
		assert.Equal(t, expectedUserInfo, userInfo)
		mockAuth.AssertExpectations(t)
	})

	t.Run("failure_empty_access_token", func(t *testing.T) {
		svc, _ := setupTest(t)

		_, err := svc.GetUserInfo(context.Background(), "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token is required")
	})

	t.Run("failure_provider_error", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		mockAuth.On("GetUserInfo", mock.Anything, "access_token").Return(nil, errors.New("provider error"))

		_, err := svc.GetUserInfo(context.Background(), "access_token")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get user info")
		mockAuth.AssertExpectations(t)
	})
	t.Run("success_with_complete_user_info", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		now := time.Now()
		expectedUserInfo := &model.UserInfo{
			ID:            "user_id",
			Email:         "test@example.com",
			EmailVerified: true,
			Name:          "Test User",
			Roles:         []string{"admin", "user"},
			Provider:      model.IdentityProviderGoogle,
			MFAInfo: &model.MFAInfo{
				Status:           model.MFAStatusEnabled,
				EnabledMethods:   []model.MFAMethod{model.MFAMethodEmail},
				DefaultMethod:    model.MFAMethodEmail,
				LastVerified:     &now,
				EnrollmentStatus: model.MFAEnrollmentComplete,
			},
			Metadata: map[string]interface{}{
				"custom_field": "value",
				"login_count":  42,
			},
		}
		mockAuth.On("GetUserInfo", mock.Anything, "access_token").Return(expectedUserInfo, nil)

		userInfo, err := svc.GetUserInfo(context.Background(), "access_token")

		assert.NoError(t, err)
		assert.Equal(t, expectedUserInfo, userInfo)
		mockAuth.AssertExpectations(t)
	})
}

func TestGetMFAStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		expectedMFAInfo := &model.MFAInfo{
			Status: model.MFAStatusEnabled,
		}
		mockAuth.On("GetMFAStatus", mock.Anything, "access_token").Return(expectedMFAInfo, nil)

		mfaInfo, err := svc.GetMFAStatus(context.Background(), "access_token")

		assert.NoError(t, err)
		assert.Equal(t, expectedMFAInfo, mfaInfo)
		mockAuth.AssertExpectations(t)
	})

	t.Run("failure_empty_access_token", func(t *testing.T) {
		svc, _ := setupTest(t)

		_, err := svc.GetMFAStatus(context.Background(), "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token is required")
	})

	t.Run("failure_provider_error", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		mockAuth.On("GetMFAStatus", mock.Anything, "access_token").Return(nil, errors.New("provider error"))

		_, err := svc.GetMFAStatus(context.Background(), "access_token")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get MFA status")
		mockAuth.AssertExpectations(t)
	})
	t.Run("success_with_multiple_methods", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		expectedMFAInfo := &model.MFAInfo{
			Status: model.MFAStatusEnabled,
			EnabledMethods: []model.MFAMethod{
				model.MFAMethodEmail,
				model.MFAMethodSMS,
			},
			DefaultMethod:    model.MFAMethodEmail,
			EnrollmentStatus: model.MFAEnrollmentComplete,
			LastVerified:     &time.Time{}, // Add specific time
		}
		mockAuth.On("GetMFAStatus", mock.Anything, "access_token").Return(expectedMFAInfo, nil)

		mfaInfo, err := svc.GetMFAStatus(context.Background(), "access_token")
		assert.NoError(t, err)
		assert.Equal(t, expectedMFAInfo, mfaInfo)
		assert.Len(t, mfaInfo.EnabledMethods, 2)
	})

	t.Run("success_with_no_mfa", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		expectedMFAInfo := &model.MFAInfo{
			Status:           model.MFAStatusDisabled,
			EnabledMethods:   []model.MFAMethod{},
			EnrollmentStatus: model.MFAEnrollmentNotStarted,
		}
		mockAuth.On("GetMFAStatus", mock.Anything, "access_token").Return(expectedMFAInfo, nil)

		mfaInfo, err := svc.GetMFAStatus(context.Background(), "access_token")
		assert.NoError(t, err)
		assert.Equal(t, model.MFAStatusDisabled, mfaInfo.Status)
		assert.Empty(t, mfaInfo.EnabledMethods)
	})
}

func TestCompleteMFAChallenge(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		expectedTokenInfo := &model.TokenInfo{
			AccessToken:  "access_token",
			RefreshToken: "refresh_token",
			TokenType:    "bearer",
			ExpiresIn:    3600,
		}
		mockAuth.On("CompleteMFAChallenge", mock.Anything, "access_token", "mfa_token").Return(expectedTokenInfo, nil)

		tokenInfo, err := svc.CompleteMFAChallenge(context.Background(), "access_token", "mfa_token")

		assert.NoError(t, err)
		assert.Equal(t, expectedTokenInfo, tokenInfo)
		mockAuth.AssertExpectations(t)
	})

	t.Run("failure_empty_access_token", func(t *testing.T) {
		svc, _ := setupTest(t)

		_, err := svc.CompleteMFAChallenge(context.Background(), "", "mfa_token")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token is required")
	})

	t.Run("failure_empty_mfa_token", func(t *testing.T) {
		svc, _ := setupTest(t)

		_, err := svc.CompleteMFAChallenge(context.Background(), "access_token", "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MFA token is required")
	})

	t.Run("failure_provider_error", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		mockAuth.On("CompleteMFAChallenge", mock.Anything, "access_token", "mfa_token").Return(nil, errors.New("provider error"))

		_, err := svc.CompleteMFAChallenge(context.Background(), "access_token", "mfa_token")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to complete MFA challenge")
		mockAuth.AssertExpectations(t)
	})
}

func TestTokenValidation(t *testing.T) {
	t.Run("validate_token_info", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		invalidTokens := []*model.TokenInfo{
			nil,
			{},
			{AccessToken: ""},
			{AccessToken: "token", TokenType: ""},
		}

		for _, token := range invalidTokens {
			mockAuth.On("ExchangeAuthorizationCode", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(token, nil).Once()

			_, err := svc.ExchangeAuthorizationCode(context.Background(), "code", "uri", "verifier", model.IdentityProviderGoogle)
			assert.Error(t, err)
		}
	})
}

func TestContextCancellation(t *testing.T) {
	t.Run("context_timeout_generate_url", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		opts := &model.AuthorizationOptions{RedirectURI: "https://example.com/callback"}
		mockAuth.On("GenerateAuthorizationURL", ctx, mock.Anything, mock.Anything, mock.Anything).
			WaitUntil(time.After(10*time.Millisecond)).
			Return("", context.DeadlineExceeded)

		_, err := svc.GenerateAuthorizationURL(ctx, model.IdentityProviderGoogle, "state", opts)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("context_cancelled", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // 即座にキャンセル

		// ここでモックの設定を追加
		mockAuth.On("GetUserInfo", mock.Anything, "access_token").
			Return(nil, context.Canceled)

		_, err := svc.GetUserInfo(ctx, "access_token")
		assert.ErrorIs(t, err, context.Canceled)
		mockAuth.AssertExpectations(t)
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("very_long_token", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		longToken := strings.Repeat("a", 10000)
		mockAuth.On("VerifyToken", mock.Anything, longToken).Return(nil, errors.New("token too long"))

		_, err := svc.VerifyToken(context.Background(), longToken)
		assert.Error(t, err)
	})

	t.Run("unusual_characters_in_token", func(t *testing.T) {
		svc, mockAuth := setupTest(t)
		unusualToken := "token\u0000with\ufffdunusual\u200bchars"
		mockAuth.On("VerifyToken", mock.Anything, unusualToken).Return(nil, errors.New("invalid token format"))

		_, err := svc.VerifyToken(context.Background(), unusualToken)
		assert.Error(t, err)
	})
}

func TestAllProviders(t *testing.T) {
	providers := []model.IdentityProvider{
		model.IdentityProviderGoogle,
		model.IdentityProviderGithub,
	}

	for _, provider := range providers {
		t.Run(fmt.Sprintf("provider_%v", provider), func(t *testing.T) {
			svc, mockAuth := setupTest(t)
			opts := &model.AuthorizationOptions{RedirectURI: "https://example.com/callback"}
			mockAuth.On("GenerateAuthorizationURL", mock.Anything, provider, mock.Anything, opts).
				Return("https://example.com/auth", nil)

			url, err := svc.GenerateAuthorizationURL(context.Background(), provider, "state", opts)
			assert.NoError(t, err)
			assert.NotEmpty(t, url)
		})
	}
}

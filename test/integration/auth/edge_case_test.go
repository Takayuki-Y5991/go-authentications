package auth_test

import (
	"testing"
	"time"

	authv1 "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
	"github.com/Takayuki-Y5991/go-authentications/test/integration/helper"
	"github.com/stretchr/testify/suite"
)

type EdgeCasesSuite struct {
	helper.AuthIntegrationTestSuite
}

func TestEdgeCases(t *testing.T) {
	suite.Run(t, new(EdgeCasesSuite))
}

func (s *EdgeCasesSuite) TestExpiredToken() {
	// Get a token that's close to expiration
	tokenResp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-code-expiring",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NoError(err)

	// Wait for token to expire (mock server should be configured to issue short-lived tokens for this test)
	time.Sleep(time.Second * 2)

	// Verify expired token
	verifyResp, err := s.AuthService.VerifyToken(s.Ctx, &authv1.VerifyTokenRequest{
		Token: tokenResp.GetAccessToken(),
	})
	s.Require().NoError(err)
	s.Require().False(verifyResp.GetIsValid())
	s.Require().Less(verifyResp.GetExpiresAt(), time.Now().Unix())
}

func (s *EdgeCasesSuite) TestRevokedRefreshToken() {
	// Get initial tokens
	tokenResp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-code",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NoError(err)

	// Simulate token revocation (mock server should be configured to recognize this token as revoked)
	refreshToken := tokenResp.GetRefreshToken()

	// Attempt to use revoked refresh token
	_, err = s.AuthService.RefreshToken(s.Ctx, &authv1.RefreshTokenRequest{
		RefreshToken: refreshToken,
	})
	s.Require().Error(err)
}

func (s *EdgeCasesSuite) TestInvalidRedirectURI() {
	// Test with mismatched redirect URI
	_, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-code",
		RedirectUri: "http://malicious-site.com/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().Error(err)
}

func (s *EdgeCasesSuite) TestInvalidScopes() {
	// Test with invalid scopes in authorization URL generation
	_, err := s.AuthService.GenerateAuthorizationURL(s.Ctx, &authv1.GenerateAuthorizationURLRequest{
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
		State:       "test-state",
		RedirectUri: "http://localhost:3000/callback",
		Scope:       []string{"invalid_scope", "another_invalid_scope"},
	})
	s.Require().Error(err)
}

func (s *EdgeCasesSuite) TestMultipleAuthorizationAttempts() {
	// Test using same authorization code multiple times
	code := "test-code"

	// First attempt should succeed
	_, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        code,
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NoError(err)

	// Second attempt with same code should fail
	_, err = s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        code,
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().Error(err)
}

func (s *EdgeCasesSuite) TestConcurrentTokenRefresh() {
	// Get initial tokens
	tokenResp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-code",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NoError(err)

	// Attempt concurrent refresh operations
	refreshToken := tokenResp.GetRefreshToken()
	done := make(chan bool)

	for i := 0; i < 3; i++ {
		go func() {
			_, err := s.AuthService.RefreshToken(s.Ctx, &authv1.RefreshTokenRequest{
				RefreshToken: refreshToken,
			})
			s.Require().NoError(err)
			done <- true
		}()
	}

	// Wait for all operations to complete
	for i := 0; i < 3; i++ {
		<-done
	}
}

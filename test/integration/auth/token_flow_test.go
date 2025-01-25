// test/integration/auth/token_test.go
package auth_test

import (
	"testing"

	authv1 "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
	"github.com/Takayuki-Y5991/go-authentications/test/integration/helper"
	"github.com/stretchr/testify/suite"
)

type TokenOperationsSuite struct {
	helper.AuthIntegrationTestSuite
}

func TestTokenOperations(t *testing.T) {
	suite.Run(t, new(TokenOperationsSuite))
}

func (s *TokenOperationsSuite) TestTokenVerification() {
	// First get a valid token
	tokenResp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-code",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NoError(err)

	// Test token verification
	verifyResp, err := s.AuthService.VerifyToken(s.Ctx, &authv1.VerifyTokenRequest{
		Token: tokenResp.GetAccessToken(),
	})
	s.Require().NoError(err)
	s.Require().True(verifyResp.GetIsValid())
}

func (s *TokenOperationsSuite) TestTokenRefresh() {
	// First get initial tokens
	initialTokens, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-code",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NoError(err)

	// Test token refresh
	refreshedTokens, err := s.AuthService.RefreshToken(s.Ctx, &authv1.RefreshTokenRequest{
		RefreshToken: initialTokens.GetRefreshToken(),
	})
	s.Require().NoError(err)
	s.Require().NotEqual(initialTokens.GetAccessToken(), refreshedTokens.GetAccessToken())
}

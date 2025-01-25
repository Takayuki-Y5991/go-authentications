package auth_test

import (
	"testing"

	authv1 "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
	"github.com/Takayuki-Y5991/go-authentications/test/integration/helper"
	"github.com/stretchr/testify/suite"
)

type BasicAuthFlowSuite struct {
	helper.AuthIntegrationTestSuite
}

func TestBasicAuthFlow(t *testing.T) {
	suite.Run(t, new(BasicAuthFlowSuite))
}

func (s *BasicAuthFlowSuite) TestAuthorizationCodeFlow() {
	// Test authorization URL generation
	authURL, err := s.AuthService.GenerateAuthorizationURL(s.Ctx, &authv1.GenerateAuthorizationURLRequest{
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
		State:       "test-state",
		RedirectUri: "http://localhost:3000/callback",
		Scope:       []string{"openid", "email", "profile"},
	})
	s.Require().NoError(err)
	s.Require().Contains(authURL.GetUrl(), s.MockServerURL)

	// Test token exchange
	tokenResp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-code",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NoError(err)
	s.Require().NotEmpty(tokenResp.GetAccessToken())
	s.Require().NotEmpty(tokenResp.GetRefreshToken())
}

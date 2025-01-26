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
	// 1. 認可URLの生成テスト
	authURL, err := s.AuthService.GenerateAuthorizationURL(s.Ctx, &authv1.GenerateAuthorizationURLRequest{
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
		State:       "test-state",
		RedirectUri: "http://localhost:3000/callback",
		Scope:       []string{"openid", "email", "profile"},
	})
	s.Require().NoError(err)
	s.Require().Contains(authURL.GetUrl(), "redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback")

	// 3. トークン交換テスト
	tokenResp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-auth-code",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NotEmpty(tokenResp.GetAccessToken())
	s.Require().NotEmpty(tokenResp.GetRefreshToken())
}

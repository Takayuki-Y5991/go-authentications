package auth_test

import (
	"testing"

	authv1 "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
	"github.com/Takayuki-Y5991/go-authentications/test/integration/helper"
	"github.com/stretchr/testify/suite"
)

// BasicAuthFlowSuite は基本的な認証フローのテストを行うスイートです
type BasicAuthFlowSuite struct {
	helper.AuthIntegrationTestSuite
}

func TestBasicAuthFlow(t *testing.T) {
	suite.Run(t, new(BasicAuthFlowSuite))
}

// TestAuthorizationCodeFlow は認可コードフローの全体をテストします
func (s *BasicAuthFlowSuite) TestAuthorizationCodeFlow() {
	// 1. 認可URLの生成
	authURLResp, err := s.AuthService.GenerateAuthorizationURL(s.Ctx, &authv1.GenerateAuthorizationURLRequest{
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
		State:       "test-state",
		RedirectUri: "http://localhost:3000/callback",
		Scope:       []string{"openid", "email", "profile"},
	})
	s.Require().NoError(err)
	s.Require().Contains(authURLResp.GetUrl(), s.MockServerURL)

	// 2. 認可コードの取得
	code := s.getMockAuthorizationCode()
	s.Require().NotEmpty(code)

	// 3. トークン交換
	tokenResp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        code,
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NoError(err)
	s.validateTokenResponse(tokenResp)

	// 4. トークン検証
	verifyResp, err := s.AuthService.VerifyToken(s.Ctx, &authv1.VerifyTokenRequest{
		Token: tokenResp.GetAccessToken(),
	})
	s.Require().NoError(err)
	s.Require().True(verifyResp.GetIsValid())

	// 5. ユーザー情報の取得
	userInfo, err := s.AuthService.GetUserInfo(s.Ctx, &authv1.GetUserInfoRequest{
		AccessToken: tokenResp.GetAccessToken(),
	})
	s.Require().NoError(err)
	s.validateUserInfo(userInfo)
}

// TestTokenRefreshFlow はトークンリフレッシュフローをテストします
func (s *BasicAuthFlowSuite) TestTokenRefreshFlow() {
	// 1. 初期トークンの取得
	initialToken := s.getValidTokenResponse()

	// 2. リフレッシュトークンの使用
	refreshResp, err := s.AuthService.RefreshToken(s.Ctx, &authv1.RefreshTokenRequest{
		RefreshToken: initialToken.GetRefreshToken(),
	})
	s.Require().NoError(err)
	s.validateTokenResponse(refreshResp)

	// 3. 新しいトークンが異なることを確認
	s.Require().NotEqual(
		initialToken.GetAccessToken(),
		refreshResp.GetAccessToken(),
		"Refreshed access token should be different",
	)
}

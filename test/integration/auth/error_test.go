// test/integration/auth/error_test.go
package auth_test

import (
	"testing"

	authv1 "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
	"github.com/Takayuki-Y5991/go-authentications/test/integration/helper"
	"github.com/stretchr/testify/suite"
)

type ErrorCasesSuite struct {
	helper.AuthIntegrationTestSuite
}

func TestErrorCases(t *testing.T) {
	suite.Run(t, new(ErrorCasesSuite))
}

func (s *ErrorCasesSuite) TestInvalidAuthorizationCode() {
	_, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "invalid-code",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().Error(err)
}

func (s *ErrorCasesSuite) TestInvalidToken() {
	verifyResp, err := s.AuthService.VerifyToken(s.Ctx, &authv1.VerifyTokenRequest{
		Token: "invalid-token",
	})
	s.Require().NoError(err)
	s.Require().False(verifyResp.GetIsValid())
}

func (s *ErrorCasesSuite) TestUnsupportedProvider() {
	_, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-code",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_UNSPECIFIED,
	})
	s.Require().Error(err)
}

func (s *ErrorCasesSuite) TestInvalidRefreshToken() {
	_, err := s.AuthService.RefreshToken(s.Ctx, &authv1.RefreshTokenRequest{
		RefreshToken: "invalid-refresh-token",
	})
	s.Require().Error(err)
}

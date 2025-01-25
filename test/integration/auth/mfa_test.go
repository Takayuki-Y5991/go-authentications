// test/integration/auth/mfa_test.go
package auth_test

import (
	"testing"

	authv1 "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
	"github.com/Takayuki-Y5991/go-authentications/test/integration/helper"
	"github.com/stretchr/testify/suite"
)

type MFAFlowSuite struct {
	helper.AuthIntegrationTestSuite
}

func TestMFAFlow(t *testing.T) {
	suite.Run(t, new(MFAFlowSuite))
}

func (s *MFAFlowSuite) TestMFARequiredFlow() {
	// Get initial tokens with MFA required
	tokenResp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-code-mfa",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NoError(err)
	s.Require().Equal(authv1.MFAStatus_MFA_STATUS_REQUIRED, tokenResp.GetMfaStatus())
	s.Require().NotEmpty(tokenResp.GetMfaToken())

	// Complete MFA challenge
	completedResp, err := s.AuthService.CompleteMFAChallenge(s.Ctx, &authv1.CompleteMFAChallengeRequest{
		AccessToken: tokenResp.GetAccessToken(),
		MfaToken:    tokenResp.GetMfaToken(),
	})
	s.Require().NoError(err)
	s.Require().Equal(authv1.MFAStatus_MFA_STATUS_ENABLED, completedResp.GetMfaStatus())
}

func (s *MFAFlowSuite) TestMFAStatusCheck() {
	// Get MFA status for a user
	tokenResp := s.getTokenWithMFA()
	status, err := s.AuthService.GetMFAStatus(s.Ctx, &authv1.GetMFAStatusRequest{
		AccessToken: tokenResp.GetAccessToken(),
	})
	s.Require().NoError(err)
	s.Require().NotNil(status.GetMfaInfo())
	s.Require().NotEmpty(status.GetMfaInfo().GetEnabledMethods())
}

func (s *MFAFlowSuite) TestInvalidMFAToken() {
	tokenResp := s.getTokenWithMFA()

	// Try to complete MFA with invalid token
	_, err := s.AuthService.CompleteMFAChallenge(s.Ctx, &authv1.CompleteMFAChallengeRequest{
		AccessToken: tokenResp.GetAccessToken(),
		MfaToken:    "invalid-mfa-token",
	})
	s.Require().Error(err)
}

// Helper method to get token with MFA required
func (s *MFAFlowSuite) getTokenWithMFA() *authv1.TokenResponse {
	resp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        "test-code-mfa",
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	s.Require().NoError(err)
	s.Require().Equal(authv1.MFAStatus_MFA_STATUS_REQUIRED, resp.GetMfaStatus())
	return resp
}

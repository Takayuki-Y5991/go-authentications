package auth_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	authv1 "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
	"github.com/Takayuki-Y5991/go-authentications/test/integration/helper"
	"github.com/stretchr/testify/suite"
)

type ConcurrencyTestSuite struct {
	helper.AuthIntegrationTestSuite
}

func TestConcurrency(t *testing.T) {
	suite.Run(t, new(ConcurrencyTestSuite))
}

// TestConcurrentAuthentication tests multiple users authenticating simultaneously
func (s *ConcurrencyTestSuite) TestConcurrentAuthentication() {
	const numUsers = 5
	var wg sync.WaitGroup
	results := make(chan error, numUsers)

	// Simulate multiple users authenticating concurrently
	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()

			// Generate authorization URL
			_, err := s.AuthService.GenerateAuthorizationURL(s.Ctx, &authv1.GenerateAuthorizationURLRequest{
				Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
				State:       fmt.Sprintf("state-user-%d", userID),
				RedirectUri: "http://localhost:3000/callback",
				Scope:       []string{"openid", "email", "profile"},
			})
			if err != nil {
				results <- err
				return
			}

			// Exchange authorization code
			tokenResp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
				Code:        fmt.Sprintf("test-code-user-%d", userID),
				RedirectUri: "http://localhost:3000/callback",
				Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
			})
			if err != nil {
				results <- err
				return
			}

			// Verify token
			_, err = s.AuthService.VerifyToken(s.Ctx, &authv1.VerifyTokenRequest{
				Token: tokenResp.GetAccessToken(),
			})
			if err != nil {
				results <- err
				return
			}

			results <- nil
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(results)

	// Check results
	for err := range results {
		s.Require().NoError(err)
	}
}

// TestConcurrentTokenRefresh tests multiple refresh token operations happening simultaneously
func (s *ConcurrencyTestSuite) TestConcurrentTokenRefresh() {
	// First get a set of valid tokens
	tokens := make([]*authv1.TokenResponse, 3)
	for i := range tokens {
		resp, err := s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
			Code:        fmt.Sprintf("test-code-%d", i),
			RedirectUri: "http://localhost:3000/callback",
			Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
		})
		s.Require().NoError(err)
		tokens[i] = resp
	}

	// Perform concurrent refresh operations
	var wg sync.WaitGroup
	results := make(chan error, len(tokens))

	for _, token := range tokens {
		wg.Add(1)
		go func(refreshToken string) {
			defer wg.Done()

			_, err := s.AuthService.RefreshToken(s.Ctx, &authv1.RefreshTokenRequest{
				RefreshToken: refreshToken,
			})
			results <- err
		}(token.GetRefreshToken())
	}

	wg.Wait()
	close(results)

	for err := range results {
		s.Require().NoError(err)
	}
}

// TestUserSessionIsolation tests that user sessions remain isolated
func (s *ConcurrencyTestSuite) TestUserSessionIsolation() {
	// Create two user sessions
	user1Token, err := s.createUserSession("user1")
	s.Require().NoError(err)

	user2Token, err := s.createUserSession("user2")
	s.Require().NoError(err)

	// Get user info for both sessions concurrently
	var wg sync.WaitGroup
	var user1Info, user2Info *authv1.UserInfoResponse
	var user1Err, user2Err error

	wg.Add(2)
	go func() {
		defer wg.Done()
		user1Info, user1Err = s.AuthService.GetUserInfo(s.Ctx, &authv1.GetUserInfoRequest{
			AccessToken: user1Token.GetAccessToken(),
		})
	}()

	go func() {
		defer wg.Done()
		user2Info, user2Err = s.AuthService.GetUserInfo(s.Ctx, &authv1.GetUserInfoRequest{
			AccessToken: user2Token.GetAccessToken(),
		})
	}()

	wg.Wait()

	// Verify results
	s.Require().NoError(user1Err)
	s.Require().NoError(user2Err)
	s.Require().NotEqual(user1Info.GetId(), user2Info.GetId())
}

// TestLoadScenario simulates a high-load scenario
func (s *ConcurrencyTestSuite) TestLoadScenario() {
	const (
		numRequests    = 50
		numConcurrent  = 10
		requestTimeout = 5 * time.Second
	)

	tokens := make(chan string, numRequests)
	errors := make(chan error, numRequests)
	rateLimiter := make(chan struct{}, numConcurrent)

	var wg sync.WaitGroup
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(reqID int) {
			defer wg.Done()
			rateLimiter <- struct{}{} // Rate limiting
			defer func() { <-rateLimiter }()

			ctx, cancel := context.WithTimeout(s.Ctx, requestTimeout)
			defer cancel()

			// Perform authentication flow
			token, err := s.performAuthFlow(ctx, reqID)
			if err != nil {
				errors <- err
				return
			}
			tokens <- token
		}(i)
	}

	wg.Wait()
	close(tokens)
	close(errors)

	// Analyze results
	successCount := len(tokens)
	errorCount := len(errors)
	s.T().Logf("Load test results: %d successful, %d failed", successCount, errorCount)
	s.Require().Zero(errorCount, "Expected no errors in load test")
}

// Helper methods

func (s *ConcurrencyTestSuite) createUserSession(userID string) (*authv1.TokenResponse, error) {
	return s.AuthService.ExchangeAuthorizationCode(s.Ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        fmt.Sprintf("test-code-%s", userID),
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
}

func (s *ConcurrencyTestSuite) performAuthFlow(ctx context.Context, reqID int) (string, error) {
	// Generate authorization URL
	_, err := s.AuthService.GenerateAuthorizationURL(ctx, &authv1.GenerateAuthorizationURLRequest{
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
		State:       fmt.Sprintf("state-%d", reqID),
		RedirectUri: "http://localhost:3000/callback",
		Scope:       []string{"openid", "email", "profile"},
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate auth URL: %w", err)
	}

	// Exchange code for tokens
	tokenResp, err := s.AuthService.ExchangeAuthorizationCode(ctx, &authv1.ExchangeAuthorizationCodeRequest{
		Code:        fmt.Sprintf("test-code-%d", reqID),
		RedirectUri: "http://localhost:3000/callback",
		Provider:    authv1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE,
	})
	if err != nil {
		return "", fmt.Errorf("failed to exchange code: %w", err)
	}

	return tokenResp.GetAccessToken(), nil
}

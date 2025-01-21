package auth0_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Takayuki-Y5991/go-authentications/pkg/adapter/outbound/auth/auth0"
	"github.com/Takayuki-Y5991/go-authentications/pkg/config"
	"github.com/Takayuki-Y5991/go-authentications/pkg/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type testServer struct {
	*httptest.Server
	requestCount int
	requestLog   []string
}

func newTestServer() *testServer {
	ts := &testServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.requestCount++
		ts.requestLog = append(ts.requestLog, r.URL.Path)
	}))
	return ts
}

func setupTest(t *testing.T) (*auth0.Auth0Provider, *testServer) {
	server := newTestServer()
	cfg := &config.Config{
		Auth0: config.Auth0Config{
			Domain:       server.URL[7:], // remove "http://"
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost/callback",
			Audience:     "test-audience",
		},
	}

	logger, _ := zap.NewDevelopment()
	provider, err := auth0.NewAuth0Adapter(cfg, logger)
	require.NoError(t, err)

	authProvider, ok := provider.(*auth0.Auth0Provider)
	require.True(t, ok, "Expected auth0.Provider type")

	return authProvider, server
}

func TestGenerateAuthorizationURL(t *testing.T) {
	t.Run("success_with_google_provider_and_pkce", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		opts := &model.AuthorizationOptions{
			RedirectURI:         "http://localhost/callback",
			CodeChallenge:       "test-challenge",
			CodeChallengeMethod: "S256",
			Scope:               []string{"additional_scope"},
			Extra:               map[string]string{"custom_param": "value"},
		}

		url, err := provider.GenerateAuthorizationURL(context.Background(), model.IdentityProviderGoogle, "test-state", opts)

		assert.NoError(t, err)
		assert.Contains(t, url, "connection=google-oauth2")
		assert.Contains(t, url, "code_challenge=test-challenge")
		assert.Contains(t, url, "code_challenge_method=S256")
		assert.Contains(t, url, "additional_scope")
		assert.Contains(t, url, "custom_param=value")
	})

	t.Run("success_with_github_provider", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		opts := &model.AuthorizationOptions{
			RedirectURI: "http://localhost/callback",
		}

		url, err := provider.GenerateAuthorizationURL(context.Background(), model.IdentityProviderGithub, "test-state", opts)

		assert.NoError(t, err)
		assert.Contains(t, url, "connection=github")
	})

	t.Run("failure_unsupported_provider", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		opts := &model.AuthorizationOptions{
			RedirectURI: "http://localhost/callback",
		}

		_, err := provider.GenerateAuthorizationURL(context.Background(), model.IdentityProviderUnspecified, "test-state", opts)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unsupported identity provider")
	})

	t.Run("failure_empty_redirect_uri", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		opts := &model.AuthorizationOptions{}

		_, err := provider.GenerateAuthorizationURL(context.Background(), model.IdentityProviderGoogle, "test-state", opts)

		assert.Error(t, err)
	})
}

func TestGetUserInfo(t *testing.T) {
	t.Run("success_complete_user_info", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":                          "user-123",
				"email":                        "test@example.com",
				"email_verified":               true,
				"name":                         "Test User",
				"picture":                      "https://example.com/avatar.jpg",
				"https://your-namespace/roles": []string{"admin", "user"},
				"user_metadata": map[string]interface{}{
					"custom_field": "value",
					"preferences": map[string]interface{}{
						"theme": "dark",
					},
				},
			})
		})

		userInfo, err := provider.GetUserInfo(context.Background(), "test-token")

		assert.NoError(t, err)
		assert.Equal(t, "user-123", userInfo.ID)
		assert.Equal(t, "test@example.com", userInfo.Email)
		assert.True(t, userInfo.EmailVerified)
		assert.Equal(t, []string{"admin", "user"}, userInfo.Roles)
		assert.NotNil(t, userInfo.Metadata)
	})

	t.Run("failure_network_error", func(t *testing.T) {
		provider, server := setupTest(t)
		server.Close() // サーバーを即座に終了させてネットワークエラーを発生させる

		_, err := provider.GetUserInfo(context.Background(), "test-token")

		assert.Error(t, err)
	})

	t.Run("failure_response_too_large", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			largeResponse := make([]byte, 2<<20)
			w.Write(largeResponse)
		})

		_, err := provider.GetUserInfo(context.Background(), "test-token")

		assert.Error(t, err)
	})
}

func TestRefreshToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "new-access-token",
				"refresh_token": "new-refresh-token",
				"expires_in":    3600,
				"token_type":    "Bearer",
			})
		})

		tokenInfo, err := provider.RefreshToken(context.Background(), "old-refresh-token")

		assert.NoError(t, err)
		assert.Equal(t, "new-access-token", tokenInfo.AccessToken)
		assert.Equal(t, "new-refresh-token", tokenInfo.RefreshToken)
	})

	t.Run("failure_expired_refresh_token", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": "Invalid refresh token",
			})
		})

		_, err := provider.RefreshToken(context.Background(), "expired-token")
		assert.Error(t, err)
	})
}

// MFA関連のテスト
func TestMFAOperations(t *testing.T) {
	t.Run("get_mfa_status", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		mfaInfo, err := provider.GetMFAStatus(context.Background(), "test-token")

		assert.NoError(t, err)
		assert.Equal(t, model.MFAStatusDisabled, mfaInfo.Status)
		assert.Empty(t, mfaInfo.EnabledMethods)
	})

	t.Run("complete_mfa_challenge", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		tokenInfo, err := provider.CompleteMFAChallenge(context.Background(), "access-token", "mfa-token")

		assert.NoError(t, err)
		assert.Equal(t, "access-token", tokenInfo.AccessToken)
		assert.Equal(t, model.MFAStatusDisabled, tokenInfo.MFAStatus)
	})
}

func TestContextCancellation(t *testing.T) {
	t.Run("context_timeout", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		})

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := provider.GetUserInfo(ctx, "test-token")
		assert.Error(t, err)
	})

	t.Run("context_cancelled", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := provider.GetUserInfo(ctx, "test-token")
		assert.Error(t, err)
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("long_response_handling", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			largeResponse := make([]byte, 2<<20)
			w.Write(largeResponse)
		})

		_, err := provider.GetUserInfo(context.Background(), "test-token")
		assert.Error(t, err)
	})

	t.Run("malformed_json_response", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"invalid json`))
		})

		_, err := provider.GetUserInfo(context.Background(), "test-token")
		assert.Error(t, err)
	})

	t.Run("unexpected_status_codes", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		unexpectedStatuses := []int{
			http.StatusNotFound,
			http.StatusInternalServerError,
			http.StatusServiceUnavailable,
		}

		for _, status := range unexpectedStatuses {
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			})

			_, err := provider.GetUserInfo(context.Background(), "test-token")
			assert.Error(t, err)
		}
	})
}
func TestVerifyToken(t *testing.T) {
	t.Run("success_valid_token", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer valid-token", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub": "user-123",
			})
		})

		result, err := provider.VerifyToken(context.Background(), "valid-token")

		assert.NoError(t, err)
		assert.True(t, result.IsValid)
		assert.NotZero(t, result.ExpiresAt)
	})

	t.Run("failure_invalid_token_format", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		result, err := provider.VerifyToken(context.Background(), "invalid-format-token")

		assert.NoError(t, err)
		assert.False(t, result.IsValid)
	})

	t.Run("failure_server_error", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, err := provider.VerifyToken(context.Background(), "token")

		assert.Error(t, err)
	})

	t.Run("success_valid_token_with_details", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer valid-token", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":            "user-123",
				"email":          "test@example.com",
				"email_verified": true,
			})
		})

		result, err := provider.VerifyToken(context.Background(), "valid-token")

		assert.NoError(t, err)
		assert.True(t, result.IsValid)
		assert.NotZero(t, result.ExpiresAt)
	})

	t.Run("failure_empty_token", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		_, err := provider.VerifyToken(context.Background(), "")
		assert.Error(t, err)
	})

	t.Run("failure_malformed_token", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		_, err := provider.VerifyToken(context.Background(), "invalid.jwt.token")
		assert.Error(t, err)
	})

	t.Run("failure_network_timeout", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
		})

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := provider.VerifyToken(ctx, "valid-token")
		assert.Error(t, err)
	})
}

func TestExchangeAuthorizationCode(t *testing.T) {
	t.Run("success_with_pkce", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "test-verifier", r.FormValue("code_verifier"))
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "new-token",
				"refresh_token": "refresh-token",
				"id_token":      "id-token",
				"expires_in":    3600,
				"token_type":    "Bearer",
			})
		})

		tokenInfo, err := provider.ExchangeAuthorizationCode(
			context.Background(),
			"code",
			"http://localhost/callback",
			"test-verifier",
			model.IdentityProviderGoogle,
		)

		assert.NoError(t, err)
		assert.NotEmpty(t, tokenInfo.AccessToken)
		assert.NotEmpty(t, tokenInfo.RefreshToken)
		assert.NotEmpty(t, tokenInfo.IDToken)
	})

	t.Run("failure_invalid_code", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": "Invalid authorization code",
			})
		})

		_, err := provider.ExchangeAuthorizationCode(
			context.Background(),
			"invalid-code",
			"http://localhost/callback",
			"test-verifier",
			model.IdentityProviderGoogle,
		)

		assert.Error(t, err)
	})

	t.Run("success_complete_response", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "test-verifier", r.FormValue("code_verifier"))
			assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
			assert.Equal(t, "test-code", r.FormValue("code"))

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "new-access-token",
				"refresh_token": "new-refresh-token",
				"id_token":      "new-id-token",
				"expires_in":    3600,
				"token_type":    "Bearer",
				"scope":         "openid profile email",
			})
		})

		tokenInfo, err := provider.ExchangeAuthorizationCode(
			context.Background(),
			"test-code",
			"http://localhost/callback",
			"test-verifier",
			model.IdentityProviderGoogle,
		)

		assert.NoError(t, err)
		assert.Equal(t, "new-access-token", tokenInfo.AccessToken)
		assert.Equal(t, "new-refresh-token", tokenInfo.RefreshToken)
		assert.Equal(t, "new-id-token", tokenInfo.IDToken)
		assert.Equal(t, int64(3600), tokenInfo.ExpiresIn)
	})

	t.Run("failure_invalid_code_with_error_details", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": "Invalid authorization code",
				"error_uri":         "https://auth0.com/docs/errors",
			})
		})

		_, err := provider.ExchangeAuthorizationCode(
			context.Background(),
			"invalid-code",
			"http://localhost/callback",
			"test-verifier",
			model.IdentityProviderGoogle,
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})

	t.Run("failure_missing_required_fields", func(t *testing.T) {
		provider, server := setupTest(t)
		defer server.Close()

		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			// アクセストークンが欠落したレスポンス
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token_type": "Bearer",
				"expires_in": 3600,
			})
		})

		_, err := provider.ExchangeAuthorizationCode(
			context.Background(),
			"test-code",
			"http://localhost/callback",
			"test-verifier",
			model.IdentityProviderGoogle,
		)

		assert.Error(t, err)
	})
}

func TestTestHelpers(t *testing.T) {
	t.Run("test_server_initialization", func(t *testing.T) {
		server := newTestServer()
		defer server.Close()

		assert.NotNil(t, server)
		assert.Equal(t, 0, server.requestCount)
		assert.Empty(t, server.requestLog)
	})

	t.Run("test_server_request_tracking", func(t *testing.T) {
		server := newTestServer()
		defer server.Close()

		paths := []string{"/test1", "/test2", "/test3"}
		for _, path := range paths {
			resp, err := http.Get(server.URL + path)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		}

		assert.Equal(t, len(paths), server.requestCount)
		assert.Equal(t, paths, server.requestLog)
	})

	t.Run("test_server_concurrent_requests", func(t *testing.T) {
		server := newTestServer()
		defer server.Close()

		const numRequests = 10
		done := make(chan bool)

		for i := 0; i < numRequests; i++ {
			go func(index int) {
				path := fmt.Sprintf("/test%d", index)
				resp, err := http.Get(server.URL + path)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				done <- true
			}(i)
		}

		// 全リクエストの完了を待つ
		for i := 0; i < numRequests; i++ {
			<-done
		}

		assert.Equal(t, numRequests, server.requestCount)
		assert.Equal(t, numRequests, len(server.requestLog))
	})
}

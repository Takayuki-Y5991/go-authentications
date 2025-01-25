package helper

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
)

// AuthIntegrationTestSuite はテストスイートの構造を定義します。
type AuthIntegrationTestSuite struct {
	suite.Suite
	Ctx             context.Context
	MockOAuthServer testcontainers.Container
	AuthService     authv1.AuthenticationServiceClient
	MockServerURL   string
	conn            *grpc.ClientConn
}

func TestAuthIntegration(t *testing.T) {
	suite.Run(t, new(AuthIntegrationTestSuite))
}

// SetupSuite はテストスイート全体の前準備を行います。
func (s *AuthIntegrationTestSuite) SetupSuite() {
	s.Ctx = context.Background()

	// Mock OAuth2サーバーのコンテナを起動
	mockServer, err := s.setupMockOAuthServer()
	s.Require().NoError(err, "Failed to start mock OAuth server")
	s.MockOAuthServer = mockServer

	// Mock OAuth2サーバーのURLを取得
	mappedPort, err := mockServer.MappedPort(s.Ctx, "8080")
	s.Require().NoError(err)
	s.MockServerURL = fmt.Sprintf("http://localhost:%s", mappedPort.Port())

	// gRPCクライアントの初期化
	conn, client, err := s.setupGRPCConnection()
	s.Require().NoError(err, "Failed to setup gRPC connection")
	s.conn = conn
	s.AuthService = client
}

// setupMockOAuthServer はMock OAuth2サーバーのコンテナを設定し起動します。
func (s *AuthIntegrationTestSuite) setupMockOAuthServer() (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/navikt/mock-oauth2-server:2.1.0",
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForHTTP("/.well-known/openid-configuration").WithPort("8080").WithStatusCodeMatcher(func(statusCode int) bool {
				return statusCode == 200
			}),
			wait.ForLog("started server on address="), // Updated log message
		),
		Env: map[string]string{
			"SERVER_PORT": "8080",
			"LOG_LEVEL":   "debug",
			"JSON_CONFIG": `{
				"interactiveLogin": true,
				"httpServer": "NettyWrapper",
				"tokenCallbacks": [
					{
						"issuerId": "default",
						"tokenExpiry": 3600,
						"requestMappings": [
							{
								"requestParam": "grant_type",
								"match": "authorization_code",
								"claims": {
									"sub": "test-user",
									"email": "test@example.com",
									"email_verified": true,
									"name": "Test User",
									"roles": ["user"]
								}
							}
						]
					}
				]
			}`,
		},
	}

	return testcontainers.GenericContainer(s.Ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

// TearDownSuite はテストスイート終了時のクリーンアップを行います。
func (s *AuthIntegrationTestSuite) TearDownSuite() {
	if s.MockOAuthServer != nil {
		err := s.MockOAuthServer.Terminate(s.Ctx)
		if err != nil {
			s.T().Log("Failed to terminate mock OAuth server:", err)
		}
	}
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *AuthIntegrationTestSuite) setupGRPCConnection() (*grpc.ClientConn, authv1.AuthenticationServiceClient, error) {
	// コンテキストにタイムアウトを設定し、リソースリークを防ぐ
	ctx, cancel := context.WithTimeout(s.Ctx, 60*time.Second)
	defer cancel()

	// 新しい推奨APIであるNewClientを使用して接続を確立
	conn, err := grpc.NewClient(
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	s.T().Logf("Initial connection state: %v", conn.GetState())

	// より効率的な接続状態の監視ループ
	// 初期状態を取得し、Ready状態になるまで監視を続ける
	for state := conn.GetState(); state != connectivity.Ready; {
		// 状態変更を待機し、タイムアウトまたはエラーが発生した場合は失敗を報告
		if !conn.WaitForStateChange(ctx, state) {
			return nil, nil, fmt.Errorf("connection timed out or failed, last state: %v", state)
		}
		// 新しい状態を取得して再評価
		state = conn.GetState()
	}

	// 接続が確立されたら、認証サービスのクライアントを作成
	authClient := authv1.NewAuthenticationServiceClient(conn)
	return conn, authClient, nil
}

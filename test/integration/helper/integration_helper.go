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
	GRPCServer      testcontainers.Container
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

	// Start the gRPC server container
	grpcServer, err := s.setupGRPCServer()
	s.Require().NoError(err, "Failed to start gRPC server")
	s.GRPCServer = grpcServer

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

func (s *AuthIntegrationTestSuite) setupGRPCServer() (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    "../../../",  // Path to the directory containing the Dockerfile
			Dockerfile: "Dockerfile", // Name of the Dockerfile
		},
		ExposedPorts: []string{"50051/tcp"},
		WaitingFor:   wait.ForLog("server started").WithStartupTimeout(2 * time.Minute), // Adjust this log message to match your server's startup log
		Env: map[string]string{
			"APP_ENV":                 "test", // テスト環境であることを明示
			"AUTH0_DOMAIN":            s.MockServerURL,
			"AUTH0_CLIENT_ID":         "test-client",
			"AUTH0_CLIENT_SECRET":     "test-secret",
			"AUTH0_AUDIENCE":          "test-api",
			"AUTH0_REDIRECT_URL":      "http://localhost:3000/callback",
			"SERVER_PORT":             "50051",
			"SERVER_SHUTDOWN_TIMEOUT": "10",
		},
	}

	container, err := testcontainers.GenericContainer(s.Ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	// Map the container's port to a host port
	mappedPort, err := container.MappedPort(s.Ctx, "50051")
	if err != nil {
		return nil, fmt.Errorf("failed to map port 50051: %w", err)
	}

	s.T().Logf("gRPC server is running on port: %s", mappedPort.Port())
	return container, nil
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
	if s.GRPCServer != nil {
		err := s.GRPCServer.Terminate(s.Ctx)
		if err != nil {
			s.T().Log("Failed to terminate gRPC server:", err)
		}
	}
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *AuthIntegrationTestSuite) setupGRPCConnection() (*grpc.ClientConn, authv1.AuthenticationServiceClient, error) {
	ctx, cancel := context.WithTimeout(s.Ctx, 180*time.Second) // Increased timeout
	defer cancel()

	// Get the mapped port for the gRPC server
	mappedPort, err := s.GRPCServer.MappedPort(s.Ctx, "50051")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get mapped port for gRPC server: %w", err)
	}

	// Use the mapped port to connect to the gRPC server
	conn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%s", mappedPort.Port()), // Use the mapped port
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	s.T().Logf("Initial connection state: %v", conn.GetState())

	// Wait for the connection to be ready
	for state := conn.GetState(); state != connectivity.Ready; {
		if !conn.WaitForStateChange(ctx, state) {
			s.T().Logf("Connection timed out or failed, last state: %v", state)
			return nil, nil, fmt.Errorf("connection timed out or failed, last state: %v", state)
		}
		state = conn.GetState()
		s.T().Logf("Connection state changed to: %v", state)
	}

	// Create authentication service client
	authClient := authv1.NewAuthenticationServiceClient(conn)
	return conn, authClient, nil
}

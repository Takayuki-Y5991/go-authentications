package helper

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	grpcD "github.com/Takayuki-Y5991/go-authentications/pkg/adapter/inbound/grpc"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	authv1 "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
	"github.com/Takayuki-Y5991/go-authentications/pkg/adapter/outbound/auth/auth0"
	"github.com/Takayuki-Y5991/go-authentications/pkg/config"
	"github.com/Takayuki-Y5991/go-authentications/pkg/port/outbound"
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
	Network         *testcontainers.DockerNetwork
}

func TestAuthIntegration(t *testing.T) {
	suite.Run(t, new(AuthIntegrationTestSuite))
}

// SetupSuite はテストスイート全体の前準備を行います。
func (s *AuthIntegrationTestSuite) SetupSuite() {

	s.Ctx = context.Background()

	os.Setenv("APP_ENV", "test")
	os.Setenv("AUTH0_DOMAIN", "localhost:8080")
	os.Setenv("AUTH0_CLIENT_ID", "test-client")
	os.Setenv("AUTH0_CLIENT_SECRET", "test-secret")
	os.Setenv("AUTH0_REDIRECT_URL", "http://http://localhost:3000/callback")

	// Load the configuration
	cfg, err := config.LoadConfig()
	s.Require().NoError(err, "Failed to load config")

	// Initialize the Auth0Provider
	authPort, err := auth0.NewAuth0Adapter(cfg, zap.NewNop())
	s.Require().NoError(err, "Failed to initialize Auth0Provider")

	// Start the Docker network
	net, err := network.New(s.Ctx,
		network.WithDriver("bridge"),
		network.WithAttachable(),
		network.WithLabels(map[string]string{
			"testcontainers": "true",
		}),
	)
	s.Require().NoError(err, "Failed to create Docker network")
	s.Network = net

	// Start the gRPC server container
	grpcServer, err := s.setupGRPCServer(authPort)

	s.Require().NoError(err, "Failed to start gRPC server")
	s.GRPCServer = grpcServer

	// Mock OAuth2サーバーのコンテナを起動
	mockServer, err := s.setupMockOAuthServer()
	s.Require().NoError(err, "Failed to start mock OAuth server")
	s.MockOAuthServer = mockServer

	// Mock OAuth2サーバーのURLを取得
	mappedPort, err := mockServer.MappedPort(s.Ctx, "8080")
	s.Require().NoError(err)
	s.MockServerURL = fmt.Sprintf("localhost:%s", mappedPort.Port())

	// gRPCクライアントの初期化
	conn, client, err := s.setupGRPCConnection()
	s.Require().NoError(err, "Failed to setup gRPC connection")
	s.conn = conn
	s.AuthService = client
}

func (s *AuthIntegrationTestSuite) setupGRPCServer(authPort outbound.AuthPort) (testcontainers.Container, error) {
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
			"AUTH0_REDIRECT_URL":      "http://localhost:3000/callback",
			"SERVER_PORT":             "50051",
			"SERVER_SHUTDOWN_TIMEOUT": "10",
		},
		Networks: []string{s.Network.Name},
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
	authHandler := grpcD.NewAuthHandler(authPort, zap.NewNop())
	router := grpcD.NewRouter(authHandler, zap.NewNop())
	router.Setup()

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
		Networks: []string{s.Network.Name},
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
							},
							{
                                "requestParam": "code",
                                "match": "test-auth-code",
                                "claims": {
                                    "sub": "subByCode",
									"aud": [
										"audByCode"
									]
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

	if s.Network != nil {
		err := s.Network.Remove(s.Ctx)
		if err != nil {
			s.T().Log("Failed to remove Docker network:", err)
		}
	}
}

func (s *AuthIntegrationTestSuite) setupGRPCConnection() (*grpc.ClientConn, authv1.AuthenticationServiceClient, error) {
	_, cancel := context.WithTimeout(s.Ctx, 180*time.Second) // Increased timeout
	defer cancel()

	// Get the mapped port for the gRPC server
	mappedPort, err := s.GRPCServer.MappedPort(s.Ctx, "50051")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get mapped port for gRPC server: %w", err)
	}

	// Use the mapped port to connect to the gRPC server
	address := fmt.Sprintf("localhost:%s", mappedPort.Port())
	var conn *grpc.ClientConn
	var authClient authv1.AuthenticationServiceClient

	// Retry mechanism
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		conn, err = grpc.NewClient(
			address,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err == nil {
			authClient = authv1.NewAuthenticationServiceClient(conn)
			break
		}
		s.T().Logf("Attempt %d: failed to create gRPC client: %v", i+1, err)
		time.Sleep(5 * time.Second) // Wait for 5 seconds before retrying
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gRPC client after %d retries: %w", maxRetries, err)
	}

	s.T().Logf("Successfully connected to gRPC server at %s", address)
	return conn, authClient, nil
}

package main

import (
	"context"
	"time"

	"github.com/Takayuki-Y5991/go-authentications/pkg/adapter/inbound/grpc"
	"github.com/Takayuki-Y5991/go-authentications/pkg/adapter/outbound/auth/auth0"
	"github.com/Takayuki-Y5991/go-authentications/pkg/config"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewProduction()

	//nolint:errcheck // Sync error is expected during shutdown
	defer logger.Sync()

	cfg, err := config.LoadConfig(".env", ".env.local")

	if err != nil {
		logger.Fatal("failed to load config", zap.Error(err))
	}

	// Auth0アダプターの初期化
	authPort, err := auth0.NewAuth0Adapter(cfg, logger)
	if err != nil {
		logger.Fatal("failed to initialize auth0 adapter", zap.Error(err))
	}

	authHandler := grpc.NewAuthHandler(authPort, logger)

	router := grpc.NewRouter(authHandler, logger)

	serverConfig := grpc.ServerConfig{
		Port:            cfg.Server.Port,
		ShutdownTimeout: time.Duration(cfg.Server.ShutdownTimeout) * time.Second,
	}
	server := grpc.NewServer(router, logger, serverConfig)

	if err := server.Start(context.Background()); err != nil {
		logger.Fatal("failed to start server", zap.Error(err))
	}
}

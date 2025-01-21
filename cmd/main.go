package main

import (
	"context"
	"os"
	"time"

	"github.com/Takayuki-Y5991/go-authentications/pkg/adapter/inbound/grpc"
	"github.com/Takayuki-Y5991/go-authentications/pkg/adapter/outbound/auth/auth0"
	"github.com/Takayuki-Y5991/go-authentications/pkg/config"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Auth0の設定を環境変数から読み込み
	cfg := &config.Config{
		Domain:       os.Getenv("AUTH0_DOMAIN"),
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		Audience:     os.Getenv("AUTH0_AUDIENCE"),
		RedirectURL:  os.Getenv("AUTH0_REDIRECT_URL"),
	}

	// Auth0アダプターの初期化
	authPort, err := auth0.NewAuth0Adapter(cfg, logger)
	if err != nil {
		logger.Fatal("failed to initialize auth0 adapter", zap.Error(err))
	}

	authHandler := grpc.NewAuthHandler(authPort, logger)

	router := grpc.NewRouter(authHandler, logger)

	serverConfig := grpc.ServerConfig{
		Port:            50051,
		ShutdownTimeout: 10 * time.Second,
	}
	server := grpc.NewServer(router, logger, serverConfig)

	if err := server.Start(context.Background()); err != nil {
		logger.Fatal("failed to start server", zap.Error(err))
	}
}

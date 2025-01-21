package grpc

import (
	"context"

	pb "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Router struct {
	server  *grpc.Server
	handler *AuthHandler
}

func NewRouter(handler *AuthHandler, logger *zap.Logger) *Router {
	// ミドルウェアの設定
	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			// リクエストIDの生成
			grpc_ctxtags.UnaryServerInterceptor(),
			// パニックハンドリング
			grpc_recovery.UnaryServerInterceptor(
				grpc_recovery.WithRecoveryHandlerContext(
					func(ctx context.Context, p interface{}) error {
						logger.Error("panic occurred", zap.Any("panic", p))
						return status.Error(codes.Internal, "internal error")
					},
				),
			),
			// ロギング
			createLoggingInterceptor(logger),
		)),
	}

	// サーバーの作成
	server := grpc.NewServer(opts...)

	return &Router{
		server:  server,
		handler: handler,
	}
}

func (r *Router) Setup() {
	pb.RegisterAuthenticationServiceServer(r.server, r.handler)
}

func (r *Router) Server() *grpc.Server {
	return r.server
}

func createLoggingInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		logger.Info("request received",
			zap.String("method", info.FullMethod),
		)

		resp, err := handler(ctx, req)

		if err != nil {
			logger.Error("request failed",
				zap.String("method", info.FullMethod),
				zap.Error(err),
			)
		} else {
			logger.Info("request completed",
				zap.String("method", info.FullMethod),
			)
		}

		return resp, err
	}
}

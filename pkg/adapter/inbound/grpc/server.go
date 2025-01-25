package grpc

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type Server struct {
	router *Router
	logger *zap.Logger
	port   int
}

type ServerConfig struct {
	Port            int
	ShutdownTimeout time.Duration
}

func NewServer(router *Router, logger *zap.Logger, config ServerConfig) *Server {
	return &Server{
		router: router,
		logger: logger,
		port:   config.Port,
	}
}

func (s *Server) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s.router.Setup()

	s.logger.Info("gRPC server is listening", zap.String("address", lis.Addr().String()))

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)

	errChan := make(chan error, 1)

	go func() {
		s.logger.Info("server started", zap.Int("port", s.port))
		if err := s.router.server.Serve(lis); err != nil {
			errChan <- fmt.Errorf("failed to serve: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down server due to context cancellation")
	case sig := <-signalChan:
		s.logger.Info("shutting down server due to signal", zap.String("signal", sig.String()))
	case err := <-errChan:
		s.logger.Error("shutting error occurred", zap.Error(err))
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	shutdownChan := make(chan struct{})
	go func() {
		s.router.server.GracefulStop()
		close(shutdownChan)
	}()

	select {
	case <-shutdownCtx.Done():
		s.logger.Warn("graceful shutdown timed out, forcing stop")
		s.router.Server().Stop()
	case <-shutdownChan:
		s.logger.Info("server shutdown completed gracefully")
	}
	return nil
}

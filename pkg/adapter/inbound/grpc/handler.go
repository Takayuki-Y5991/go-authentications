package grpc

import (
	"context"

	pb "github.com/Takayuki-Y5991/go-authentications/gen/proto/auth/v1"
	"github.com/Takayuki-Y5991/go-authentications/pkg/domain/model"
	"github.com/Takayuki-Y5991/go-authentications/pkg/port/inbound"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthHandler struct {
	pb.UnimplementedAuthenticationServiceServer
	authPort inbound.GRPCPort
	logger   *zap.Logger
}

func NewAuthHandler(authPort inbound.GRPCPort, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		authPort: authPort,
		logger:   logger,
	}
}

func (h *AuthHandler) GenerateAuthorizationURL(ctx context.Context, req *pb.GenerateAuthorizationURLRequest) (*pb.GenerateAuthorizationURLResponse, error) {
	opts := &model.AuthorizationOptions{
		RedirectURI:         req.RedirectUri,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}

	url, err := h.authPort.GenerateAuthorizationURL(ctx, model.IdentityProvider(req.Provider), req.State, opts)
	if err != nil {
		h.logger.Error("Failed to generate authorization URL", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to generate authorization URL")
	}
	return &pb.GenerateAuthorizationURLResponse{Url: url}, nil
}

func convertToModelProvider(provider pb.IdentityProvider) model.IdentityProvider {
	switch provider {
	case pb.IdentityProvider_IDENTITY_PROVIDER_GOOGLE:
		return model.IdentityProviderGoogle
	case pb.IdentityProvider_IDENTITY_PROVIDER_GITHUB:
		return model.IdentityProviderGithub
	default:
		return model.IdentityProviderUnspecified
	}
}

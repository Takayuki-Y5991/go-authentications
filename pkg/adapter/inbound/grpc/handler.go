package grpc

import (
	"context"
	"fmt"
	"strconv"

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

func (h *AuthHandler) ExchangeAuthorizationCode(ctx context.Context, req *pb.ExchangeAuthorizationCodeRequest) (*pb.TokenResponse, error) {
	tokenInfo, err := h.authPort.ExchangeAuthorizationCode(ctx, req.Code, req.RedirectUri, req.CodeVerifier, convertToModelProvider(req.Provider))
	if err != nil {
		h.logger.Error("Failed to exchange authorization code", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to exchange authorization code")
	}
	return convertToProtoTokenResponse(tokenInfo), nil
}

func (h *AuthHandler) VerifyToken(ctx context.Context, req *pb.VerifyTokenRequest) (*pb.VerifyTokenResponse, error) {
	result, err := h.authPort.VerifyToken(ctx, req.Token)
	if err != nil {
		h.logger.Error("Failed to verify token", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to verify token")
	}
	return &pb.VerifyTokenResponse{
		IsValid:      result.IsValid,
		Scopes:       result.Scopes,
		ExpiresAt:    result.ExpiresAt.Unix(),
		MfaCompleted: result.MFACompleted}, nil
}

func (h *AuthHandler) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.TokenResponse, error) {
	tokenInfo, err := h.authPort.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		h.logger.Error("Failed to refresh token", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to refresh token")
	}
	return convertToProtoTokenResponse(tokenInfo), nil
}

func (h *AuthHandler) GetUserInfo(ctx context.Context, req *pb.GetUserInfoRequest) (*pb.UserInfoResponse, error) {
	userInfo, err := h.authPort.GetUserInfo(ctx, req.AccessToken)
	if err != nil {
		h.logger.Error("Failed to get user info", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to get user info")
	}
	return &pb.UserInfoResponse{
		Id:            userInfo.ID,
		Email:         userInfo.Email,
		EmailVerified: userInfo.EmailVerified,
		Name:          userInfo.Name,
		Roles:         userInfo.Roles,
		Provider:      convertToProtoProvider(userInfo.Provider),
		MfaInfo:       convertToProtoMFAInfo(userInfo.MFAInfo),
		Metadata:      convertMapToStringMap(userInfo.Metadata),
	}, nil
}

func (h *AuthHandler) GetMFAStatus(ctx context.Context, req *pb.GetMFAStatusRequest) (*pb.GetMFAStatusResponse, error) {
	mfaInfo, err := h.authPort.GetMFAStatus(ctx, req.AccessToken)
	if err != nil {
		h.logger.Error("failed to get MFA status", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to get MFA status")
	}

	return &pb.GetMFAStatusResponse{
		MfaInfo: convertToProtoMFAInfo(mfaInfo),
	}, nil
}

func (h *AuthHandler) CompleteMFAChallenge(ctx context.Context, req *pb.CompleteMFAChallengeRequest) (*pb.TokenResponse, error) {
	tokenInfo, err := h.authPort.CompleteMFAChallenge(ctx, req.AccessToken, req.MfaToken)
	if err != nil {
		h.logger.Error("failed to complete MFA challenge", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to complete MFA challenge")
	}

	return convertToProtoTokenResponse(tokenInfo), nil
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

func convertToProtoProvider(provider model.IdentityProvider) pb.IdentityProvider {
	switch provider {
	case model.IdentityProviderGoogle:
		return pb.IdentityProvider_IDENTITY_PROVIDER_GOOGLE
	case model.IdentityProviderGithub:
		return pb.IdentityProvider_IDENTITY_PROVIDER_GITHUB
	default:
		return pb.IdentityProvider_IDENTITY_PROVIDER_UNSPECIFIED
	}
}

func convertToProtoMFAStatus(status model.MFAStatus) pb.MFAStatus {
	switch status {
	case model.MFAStatusDisabled:
		return pb.MFAStatus_MFA_STATUS_DISABLED
	case model.MFAStatusEnabled:
		return pb.MFAStatus_MFA_STATUS_ENABLED
	case model.MFAStatusRequired:
		return pb.MFAStatus_MFA_STATUS_REQUIRED
	default:
		return pb.MFAStatus_MFA_STATUS_UNSPECIFIED
	}
}

func convertToProtoMFAMethod(method model.MFAMethod) pb.MFAMethod {
	switch method {
	case model.MFAMethodSMS:
		return pb.MFAMethod_MFA_METHOD_SMS
	case model.MFAMethodEmail:
		return pb.MFAMethod_MFA_METHOD_EMAIL
	default:
		return pb.MFAMethod_MFA_METHOD_UNSPECIFIED
	}
}

func convertToProtoMFAInfo(info *model.MFAInfo) *pb.MFAInfo {
	if info == nil {
		return nil
	}

	methods := make([]pb.MFAMethod, len(info.EnabledMethods))
	for i, method := range info.EnabledMethods {
		methods[i] = convertToProtoMFAMethod(method)
	}

	var lastVerifiedAt int64
	if info.LastVerified != nil {
		lastVerifiedAt = info.LastVerified.Unix()
	}

	return &pb.MFAInfo{
		Status:         convertToProtoMFAStatus(info.Status),
		EnabledMethods: methods,
		DefaultMethod:  convertToProtoMFAMethod(info.DefaultMethod),
		LastVerifiedAt: lastVerifiedAt,
	}
}

func convertToProtoTokenResponse(tokenInfo *model.TokenInfo) *pb.TokenResponse {
	if tokenInfo == nil {
		return nil
	}

	return &pb.TokenResponse{
		AccessToken:  tokenInfo.AccessToken,
		RefreshToken: tokenInfo.RefreshToken,
		ExpiresIn:    tokenInfo.ExpiresIn,
		TokenType:    tokenInfo.TokenType,
		Scope:        tokenInfo.Scopes,
		MfaStatus:    convertToProtoMFAStatus(tokenInfo.MFAStatus),
		MfaToken:     tokenInfo.MFAToken,
		IdToken:      tokenInfo.IDToken,
	}
}
func convertMapToStringMap(m map[string]interface{}) map[string]string {
	if m == nil {
		return nil
	}

	result := make(map[string]string)
	for k, v := range m {
		// interface{}の値を文字列に変換
		switch val := v.(type) {
		case string:
			result[k] = val
		case int:
			result[k] = strconv.Itoa(val)
		case float64:
			result[k] = strconv.FormatFloat(val, 'f', -1, 64)
		case bool:
			result[k] = strconv.FormatBool(val)
		default:
			// その他の型は文字列化して保存
			result[k] = fmt.Sprintf("%v", val)
		}
	}
	return result
}

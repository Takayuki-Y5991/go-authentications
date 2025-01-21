package outbound

import (
	"context"

	"github.com/Takayuki-Y5991/go-authentications/pkg/domain/model"
)

type UserRepositoryPort interface {
	FindByID(ctx context.Context, userID string) (*model.UserInfo, error)
	SaveMFAStatus(ctx context.Context, userID string, mfaInfo *model.MFAInfo) error
}

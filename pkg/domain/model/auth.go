package model

import "time"

type TokenInfo struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
	Scopes       []string
	MFAStatus    MFAStatus
	MFAToken     string
	IDToken      string // OpenID connect
	IssuedAt     time.Time
}

type VerificationResult struct {
	IsValid      bool
	Scopes       []string
	ExpiresAt    time.Time
	UserID       string
	MFACompleted bool
}

type UserInfo struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Roles         []string
	Provider      IdentityProvider
	MFAInfo       *MFAInfo
	Metadata      map[string]interface{}
}

type MFAInfo struct {
	Status           MFAStatus
	EnabledMethods   []MFAMethod
	DefaultMethod    MFAMethod
	LastVerified     *time.Time
	EnrollmentStatus MFAEnrollmentStatus
}

type AuthorizationOptions struct {
	RedirectURI         string
	Scope               []string
	CodeChallenge       string            // PKCE用
	CodeChallengeMethod string            // PKCE用（S256推奨）
	Prompt              string            // login, consent, select_account など
	MaxAge              int               // 最大認証経過時間（秒）
	ResponseMode        string            // query, fragment など
	Nonce               string            // OpenID Connect用
	Display             string            // page, popup, touch, wap
	LoginHint           string            // 事前入力するメールアドレスなど
	UILocales           []string          // UI言語設定
	IDTokenHint         string            // 以前取得したIDトークン
	Extra               map[string]string // その他のパラメータ
}

type MFAStatus int

const (
	MFAStatusUnspecified MFAStatus = iota
	MFAStatusDisabled
	MFAStatusEnabled
	MFAStatusRequired
	MFAStatusPending
)

type MFAMethod int

const (
	MFAMethodUnspecified MFAMethod = iota
	MFAMethodAuthenticator
	MFAMethodSMS
	MFAMethodEmail
)

type MFAEnrollmentStatus int

const (
	MFAEnrollmentUnspecified MFAEnrollmentStatus = iota
	MFAEnrollmentNotStarted
	MFAEnrollmentPending
	MFAEnrollmentComplete
)

type IdentityProvider int

const (
	IdentityProviderUnspecified IdentityProvider = iota
	IdentityProviderGoogle
	IdentityProviderGithub
)

type AuthError struct {
	Code    ErrorCode
	Message string
	Details map[string]interface{}
}

type ErrorCode int

const (
	ErrorUnspecified ErrorCode = iota
	ErrorInvalidToken
	ErrorTokenExpired
	ErrorInvalidRequest
	ErrorProviderNotSupported
	ErrorServerError
	ErrorMFARequired
	ErrorMFAInvalid
	ErrorMFAExpired
)

func (e *AuthError) Error() string {
	return e.Message
}

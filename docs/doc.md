├── Makefile
├── buf.yaml
├── buf.gen.yaml
├── buf.lock
├── go.mod
├── go.sum
│
├── cmd
│   └── auth-service
│       └── main.go
│
├── proto                    # Protocol Buffersの定義
│   └── auth
│       └── v1
│           └── auth.proto
│
├── pkg
│   ├── domain              # ドメイン層
│   │   ├── model          # ドメインモデル
│   │   │   ├── auth.go
│   │   │   └── user.go
│   │   └── service        # ドメインサービス
│   │       └── auth.go
│   │
│   ├── port               # ポート定義
│   │   ├── inbound       # 入力ポート（プライマリ）
│   │   │   ├── grpc.go   # gRPC用ポート
│   │   │   └── http.go   # HTTP用ポート（必要な場合）
│   │   └── outbound      # 出力ポート（セカンダリ）
│   │       ├── auth_provider.go  # 認証プロバイダー用ポート
│   │       └── repository.go     # リポジトリ用ポート
│   │
│   ├── adapter                  # アダプター実装
│   │   ├── inbound             # 入力アダプター
│   │   │   ├── grpc           # gRPCアダプター
│   │   │   │   ├── handler    # gRPCハンドラー
│   │   │   │   │   └── auth.go
│   │   │   │   ├── router.go  # gRPCルーティング
│   │   │   │   └── server.go  # gRPCサーバー設定
│   │   │   └── http          # HTTPアダプター（必要な場合）
│   │   │       ├── handler
│   │   │       ├── router.go
│   │   │       └── server.go
│   │   └── outbound          # 出力アダプター
│   │       ├── auth         # 認証プロバイダーアダプター
│   │       │   ├── auth0
│   │       │   │   └── client.go
│   │       │   └── keycloak
│   │       │       └── client.go
│   │       └── repository   # リポジトリアダプター
│   │           └── auth.go
│   │
│   └── config              # 設定
│       └── config.go
│
├── gen                     # 生成されたコード
│   └── auth
│       └── v1
│           ├── auth.pb.go
│           └── auth_grpc.pb.go
│
└── test
    ├── integration         # 統合テスト
    │   └── auth_test.go
    ├── mock               # モックオブジェクト
    │   ├── inbound
    │   │   └── grpc_mock.go
    │   └── outbound
    │       ├── auth_provider_mock.go
    │       └── repository_mock.go
    └── unit              # 単体テスト
        ├── adapter
        │   ├── inbound
        │   │   └── grpc_test.go
        │   └── outbound
        │       ├── auth0_test.go
        │       └── keycloak_test.go
        └── domain
            └── service
                └── auth_test.go
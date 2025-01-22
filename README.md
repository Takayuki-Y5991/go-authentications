Here’s a comprehensive `README.md` file for your project. It includes an overview, setup instructions, usage examples, and details about the gRPC service and protobuf definitions.

---

# Go Authentication Service

This project provides a gRPC-based authentication service that supports OAuth2.0, token verification, user information retrieval, and multi-factor authentication (MFA). It integrates with identity providers like Google and GitHub and uses Auth0 for authentication.

## Table of Contents

1. [Features](#features)
2. [Getting Started](#getting-started)
   - [Prerequisites](#prerequisites)
   - [Installation](#installation)
   - [Configuration](#configuration)
3. [Running the Service](#running-the-service)
4. [gRPC API Documentation](#grpc-api-documentation)
5. [Testing](#testing)
6. [Code Generation](#code-generation)
7. [Linting](#linting)
8. [Contributing](#contributing)
9. [License](#license)

---

## Features

- **OAuth2.0 Integration**: Supports Google and GitHub as identity providers.
- **Token Management**: Generate, verify, and refresh access tokens.
- **User Information**: Retrieve user details such as email, roles, and metadata.
- **Multi-Factor Authentication (MFA)**: Supports MFA status checks and challenge completion.
- **gRPC API**: Provides a well-defined gRPC interface for authentication and authorization.

---

## Getting Started

### Prerequisites

- Go 1.20 or higher
- Protocol Buffers (`protoc`)
- Buf CLI (`buf`)
- Auth0 account (for OAuth2.0 integration)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Takayuki-Y5991/go-authentications.git
   cd go-authentications
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Install development tools:
   ```bash
   make tools
   ```

### Configuration

Create a `.env` file in the root directory with the following environment variables:

```env
AUTH0_DOMAIN=your-auth0-domain
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_AUDIENCE=https://api.example.com
AUTH0_REDIRECT_URL=https://example.com/callback
SERVER_PORT=50051
SERVER_SHUTDOWN_TIMEOUT=10
```

---

## Running the Service

1. Build the application:
   ```bash
   make build
   ```

2. Run the service:
   ```bash
   make run
   ```

3. The service will start on the specified port (`SERVER_PORT`). You can interact with it using a gRPC client.

---

## gRPC API Documentation

The service provides the following gRPC methods:

### AuthenticationService

- **GenerateAuthorizationURL**: Generates an OAuth2.0 authorization URL.
- **ExchangeAuthorizationCode**: Exchanges an authorization code for tokens.
- **VerifyToken**: Validates an access token.
- **RefreshToken**: Obtains a new access token using a refresh token.
- **GetUserInfo**: Retrieves authenticated user information.
- **GetMFAStatus**: Retrieves the current MFA configuration and status.
- **CompleteMFAChallenge**: Verifies an MFA challenge and returns a new token.

For detailed request and response structures, refer to the [protobuf definitions](#protobuf-definitions).

---

## Testing

### Running Tests

1. Run all tests:
   ```bash
   make test
   ```

2. Run unit tests only:
   ```bash
   make test-unit
   ```

3. Run integration tests:
   ```bash
   make test-integration
   ```

4. Run tests with coverage:
   ```bash
   make test-coverage
   ```

### Test Output

- **Verbose Output**: Use `make test-verbose` for detailed test output.
- **JSON Output**: Use `make test-json` to generate a JSON test report.

---

## Code Generation

The project uses Protocol Buffers for gRPC API definitions. To generate Go code from the `.proto` files:

```bash
make generate
```

This will generate the necessary Go files in the `gen/proto` directory.

---

## Linting

### Run Linter

```bash
make lint
```

### Fix Linting Issues

```bash
make lint-fix
```

---

## Protobuf Definitions

The gRPC API is defined using Protocol Buffers. Below is an overview of the `.proto` file:

### Service Definition

```proto
service AuthenticationService {
  rpc GenerateAuthorizationURL(GenerateAuthorizationURLRequest) returns (GenerateAuthorizationURLResponse);
  rpc ExchangeAuthorizationCode(ExchangeAuthorizationCodeRequest) returns (TokenResponse);
  rpc VerifyToken(VerifyTokenRequest) returns (VerifyTokenResponse);
  rpc RefreshToken(RefreshTokenRequest) returns (TokenResponse);
  rpc GetUserInfo(GetUserInfoRequest) returns (UserInfoResponse);
  rpc GetMFAStatus(GetMFAStatusRequest) returns (GetMFAStatusResponse);
  rpc CompleteMFAChallenge(CompleteMFAChallengeRequest) returns (TokenResponse);
}
```

### Message Definitions

- **GenerateAuthorizationURLRequest**: Request to generate an OAuth2.0 authorization URL.
- **TokenResponse**: Common response format for token-related operations.
- **VerifyTokenRequest/VerifyTokenResponse**: Request and response for token verification.
- **UserInfoResponse**: Response containing user information.
- **MFAInfo**: Structure for MFA configuration and status.

For the full `.proto` file, refer to [proto/auth/v1/auth.proto](proto/auth/v1/auth.proto).

---

This `README.md` provides a comprehensive guide to setting up, running, and contributing to the project. Let me know if you need further assistance!
# Mock OIDC Server

A mock OpenID Connect server written in Go that follows the OIDC specification. This server is designed for testing and development purposes.

## Features

- OIDC compliant endpoints
- User authentication from JSON files
- Automatic PKI generation
- Well-known endpoint support
- Custom claims support
- Built with Go standard library where possible
- Supports Authorization Code, Password Grant, and Client Credentials flows
- **Comprehensive structured logging** with debug support

## Setup

1. Install Go 1.21 or later

2. Create directories containing JSON files for users and client applications:

   **Users directory** - Create a directory containing JSON files for each user. Example user file:
```json
{
    "username": "testuser",
    "password": "password123",
    "claims": {
        "name": "Test User",
        "email": "test@example.com",
        "sub": "testuser"
    }
}
```

   **Client Applications directory** - Create a directory containing JSON files for each client application. Example client file:
```json
{
    "client_id": "testapp",
    "client_secret": "secret123",
    "claims": {
        "name": "Test Application",
        "app_type": "service",
        "permissions": ["read", "write"],
        "scope": "api"
    }
}
```

3. Run the server:
```bash
# Basic usage with default settings
go run main.go

# Run with debug logging (recommended for troubleshooting)
go run main.go --debug

# Specify custom users and apps directories
go run main.go -users-dir /path/to/users -apps-dir /path/to/apps

# Full configuration example with debug logging
go run main.go --debug -users-dir /path/to/users -apps-dir /path/to/apps -host 0.0.0.0 -port 9090 -issuer http://my-issuer.com
```

## Docker

The application can be run in Docker with all templates and dependencies included:

```bash
# Build the Docker image
docker build -t mock-oidc .

# Run the container
docker run -p 8080:8080 mock-oidc

# Run with debug logging
docker run -p 8080:8080 mock-oidc --debug

# Run with custom configuration
docker run -p 8080:8080 -v /path/to/users:/app/users -v /path/to/apps:/app/apps mock-oidc --debug -users-dir /app/users -apps-dir /app/apps
```

The Docker image includes:
- All required templates (`templates/login.html`)
- Default user configuration
- Proper file permissions and directory structure

## Command-line Flags

- `-users-dir`: Directory containing user JSON files (default: `./users`)
- `-apps-dir`: Directory containing client application JSON files (default: `./apps`)
- `-host`: Server host (default: `localhost`)
- `-port`: Server port (default: `8080`)
- `-issuer`: OIDC issuer URL (defaults to `http://{host}:{port}`)
- `--debug`: Enable debug-level logging (default: info level)

## Logging

The server includes comprehensive structured logging using Go's `slog` library. This makes it much easier to debug integration issues when using the server in other projects.

### Log Levels
- **INFO** (default): General operational information
- **DEBUG**: Detailed diagnostic information (use `--debug` flag)
- **WARN**: Warning messages for potential issues
- **ERROR**: Error messages for failed operations

### Features
- **Request tracking**: Each request gets a unique ID for easy tracing
- **Structured JSON logs**: Easy to parse and analyze
- **Context-aware logging**: User, client, and endpoint context
- **Security monitoring**: Authentication attempts and failures
- **Performance metrics**: Timing and resource usage

For detailed logging documentation, see [LOGGING.md](LOGGING.md).

### Quick Debugging
```bash
# Start with debug logging
./mock-oidc --debug

# Test the logging
./test_logging.sh
```

## Endpoints

- `/.well-known/openid-configuration` - OIDC discovery endpoint
- `/oauth2/authorize` - Authorization endpoint
- `/oauth2/login` - Login page endpoint
- `/oauth2/token` - Token endpoint
- `/oauth2/userinfo` - UserInfo endpoint
- `/oauth2/jwks.json` - JWKS endpoint

## Usage Examples

### Authorization Code Flow

1. Redirect the user to the authorization endpoint:
```
GET /oauth2/authorize?
    client_id=client&
    redirect_uri=http://client/callback&
    response_type=code&
    state=xyz&
    scope=openid
```

2. User will see the login page and enter their credentials

3. After successful login, the server redirects to the client with an authorization code:
```
http://client/callback?code=abc123&state=xyz
```

4. Exchange the authorization code for tokens:
```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=abc123&
client_id=client&
redirect_uri=http://client/callback
```

### Password Grant Flow

Request tokens directly with username and password:
```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&
username=testuser&
password=password123&
scope=openid
```

### Client Credentials Grant Flow

Request tokens for client applications (machine-to-machine):
```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=testapp&
client_secret=secret123
```

Or using Basic authentication:
```
POST /oauth2/token
Authorization: Basic dGVzdGFwcDpzZWNyZXQxMjM=
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

**Note**: Client credentials grant returns only an `access_token`, no `id_token`.

### Token Response

User-based flows (authorization_code, password) return:
```json
{
    "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTBhYmNkZWYifQ...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "id_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTBhYmNkZWYifQ..."
}
```

Client credentials flow returns:
```json
{
    "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTBhYmNkZWYifQ...",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

### UserInfo Endpoint

Get user information using the access token:
```
GET /oauth2/userinfo
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTBhYmNkZWYifQ...
```

Response:
```json
{
    "sub": "testuser",
    "name": "Test User",
    "email": "test@example.com"
}
```

### JWKS Endpoint

Get the JSON Web Key Set for token validation:
```
GET /oauth2/jwks.json
```

Response:
```json
{
    "keys": [
        {
            "kid": "1234567890abcdef",
            "kty": "EC",
            "crv": "P-256",
            "x": "...",
            "y": "...",
            "use": "sig",
            "alg": "ES256",
            "key_ops": ["verify"]
        }
    ]
}
```

## Project Structure

```
.
├── internal/
│   ├── config/
│   │   └── config.go
│   ├── handlers/
│   │   └── oidc.go
│   ├── models/
│   │   └── user.go
│   ├── pki/
│   │   └── pki.go
│   └── session/
│       └── session.go
├── templates/
│   └── login.html
├── users/
│   └── testuser.json
├── main.go
├── go.mod
└── README.md
``` 
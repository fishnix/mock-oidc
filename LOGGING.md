# OIDC Server Logging

This OIDC server includes comprehensive structured logging using Go's `slog` library. The logging system provides detailed insights into all operations, making it much easier to debug issues when using the application in other projects.

## Features

### Log Levels
- **INFO** (default): General operational information
- **DEBUG**: Detailed diagnostic information (enabled with `--debug` flag)
- **WARN**: Warning messages for potential issues
- **ERROR**: Error messages for failed operations

### Structured Logging
All log messages are in JSON format with structured fields for easy parsing and analysis:

```json
{
  "time": "2025-06-20T16:59:49Z",
  "level": "INFO",
  "msg": "Handling well-known configuration request",
  "request_id": "958774e378442092",
  "endpoint": "well-known-configuration",
  "method": "GET",
  "remote_addr": "127.0.0.1:32946",
  "user_agent": "curl/7.74.0"
}
```

### Request Tracking
Each HTTP request gets a unique request ID that is included in all log messages for that request, making it easy to trace the complete flow of a single request.

### Context-Aware Logging
Loggers can be enhanced with additional context:
- **User context**: `WithUser(username)`
- **Client context**: `WithClient(clientID)`
- **Endpoint context**: `WithEndpoint(endpoint)`
- **Request ID context**: `WithRequestID(requestID)`

## Usage

### Command Line Options

```bash
# Run with default info-level logging
./mock-oidc

# Run with debug-level logging (recommended for troubleshooting)
./mock-oidc --debug

# Run with custom configuration and debug logging
./mock-oidc --debug --port 8081 --host 0.0.0.0
```

### Log Output Examples

#### Server Startup
```json
{
  "time": "2025-06-20T16:59:47Z",
  "level": "INFO",
  "msg": "Starting OIDC server",
  "debug": true,
  "log_level": "debug",
  "host": "localhost",
  "port": "8081",
  "users_dir": "./users"
}
```

#### Request Processing
```json
{
  "time": "2025-06-20T16:59:49Z",
  "level": "INFO",
  "msg": "Handling authorization request",
  "request_id": "2673cc153ed6576f",
  "endpoint": "authorize",
  "method": "GET",
  "remote_addr": "127.0.0.1:32970",
  "user_agent": "curl/7.74.0",
  "url": "/oauth2/authorize?client_id=test&redirect_uri=http://localhost:3000/callback&state=123&response_type=code"
}
```

#### Authentication Events
```json
{
  "time": "2025-06-20T16:59:49Z",
  "level": "WARN",
  "msg": "Login attempt with non-existent user",
  "request_id": "89796082c55e79ff",
  "endpoint": "login",
  "username": "invaliduser"
}
```

#### Error Handling
```json
{
  "time": "2025-06-20T16:59:49Z",
  "level": "ERROR",
  "msg": "Failed to parse login template",
  "request_id": "2673cc153ed6576f",
  "endpoint": "authorize",
  "error": "open templates/login.html: no such file or directory"
}
```

## What Gets Logged

### Application Startup
- Configuration loading and validation
- Key pair generation
- User loading from files
- Server initialization

### HTTP Requests
- All incoming requests with method, URL, and client information
- Request parameter validation
- Response generation
- Error conditions

### Authentication & Authorization
- Login attempts (successful and failed)
- Password validation
- Authorization code generation and validation
- Token creation and validation

### Security Events
- Invalid authorization codes
- Expired tokens
- Missing or invalid parameters
- Unauthorized access attempts

### Performance Metrics
- Key generation timing
- User loading statistics
- Active authorization code counts

## Debug Mode

When running with `--debug`, additional information is logged:

- Source file and line numbers for all log messages
- Detailed parameter values (with sensitive data redacted)
- Internal operation details
- Configuration values
- File system operations

## Integration with Other Projects

When using this OIDC server in other projects, the comprehensive logging will help you:

1. **Troubleshoot Integration Issues**: Track the complete OAuth2/OIDC flow
2. **Monitor Security**: Identify suspicious authentication attempts
3. **Performance Analysis**: Understand timing and resource usage
4. **Debug Configuration**: Verify settings and environment variables

### Example Debugging Workflow

1. Start the server with debug logging: `./mock-oidc --debug`
2. Reproduce the issue in your application
3. Look for the request ID in the logs to trace the complete flow
4. Check for any ERROR or WARN messages
5. Verify parameter values and configuration

### Log Analysis Tips

- **Filter by request_id**: Use `jq` or similar tools to filter logs by request ID
- **Look for ERROR level**: These indicate actual problems that need attention
- **Check WARN level**: These indicate potential issues or security concerns
- **Monitor authentication patterns**: Look for repeated failed login attempts

## Testing the Logging

To see the logging in action, start the server with debug mode and make some requests:

```bash
# Start with debug logging
./mock-oidc --debug

# In another terminal, test the endpoints
curl http://localhost:8080/.well-known/openid-configuration
curl http://localhost:8080/oauth2/jwks.json
curl "http://localhost:8080/oauth2/authorize?client_id=test&redirect_uri=http://localhost:3000/callback&state=123&response_type=code"
```

This will demonstrate all the logging features and show you what to expect when using the server. 
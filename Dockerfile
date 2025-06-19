# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod and sum files
COPY go.mod ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o mock-oidc

# Final stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy the binary from builder
COPY --from=builder /app/mock-oidc .

# Create users directory
RUN mkdir -p /app/users

# Copy default user if exists
COPY users/testuser.json /app/users/

# Expose the default port
EXPOSE 8080

# Set environment variables
ENV OIDC_HOST=0.0.0.0
ENV OIDC_PORT=8080

# Run the application
CMD ["./mock-oidc"] 
package logger

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// Level represents the logging level
type Level string

const (
	DebugLevel Level = "debug"
	InfoLevel  Level = "info"
	WarnLevel  Level = "warn"
	ErrorLevel Level = "error"
)

// Logger wraps slog.Logger to provide additional functionality
type Logger struct {
	*slog.Logger
}

var defaultLogger *Logger

// Init initializes the global logger with the specified level
func Init(level Level) {
	var slogLevel slog.Level
	switch level {
	case DebugLevel:
		slogLevel = slog.LevelDebug
	case InfoLevel:
		slogLevel = slog.LevelInfo
	case WarnLevel:
		slogLevel = slog.LevelWarn
	case ErrorLevel:
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level:     slogLevel,
		AddSource: level == DebugLevel, // Add source location for debug level
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Customize timestamp format
			if a.Key == slog.TimeKey {
				return slog.Attr{
					Key:   slog.TimeKey,
					Value: slog.StringValue(a.Value.Time().Format(time.RFC3339)),
				}
			}
			return a
		},
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)
	defaultLogger = &Logger{Logger: logger}
}

// Get returns the global logger instance
func Get() *Logger {
	if defaultLogger == nil {
		// Initialize with default info level if not initialized
		Init(InfoLevel)
	}
	return defaultLogger
}

// WithRequestID creates a logger with request ID context
func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{Logger: l.With("request_id", requestID)}
}

// WithUser creates a logger with user context
func (l *Logger) WithUser(username string) *Logger {
	return &Logger{Logger: l.With("user", username)}
}

// WithClient creates a logger with client context
func (l *Logger) WithClient(clientID string) *Logger {
	return &Logger{Logger: l.With("client_id", clientID)}
}

// WithEndpoint creates a logger with endpoint context
func (l *Logger) WithEndpoint(endpoint string) *Logger {
	return &Logger{Logger: l.With("endpoint", endpoint)}
}

// Debug logs a debug message with optional attributes
func (l *Logger) Debug(msg string, args ...any) {
	l.Logger.Debug(msg, args...)
}

// Info logs an info message with optional attributes
func (l *Logger) Info(msg string, args ...any) {
	l.Logger.Info(msg, args...)
}

// Warn logs a warning message with optional attributes
func (l *Logger) Warn(msg string, args ...any) {
	l.Logger.Warn(msg, args...)
}

// Error logs an error message with optional attributes
func (l *Logger) Error(msg string, args ...any) {
	l.Logger.Error(msg, args...)
}

// DebugContext logs a debug message with context
func (l *Logger) DebugContext(ctx context.Context, msg string, args ...any) {
	l.Logger.DebugContext(ctx, msg, args...)
}

// InfoContext logs an info message with context
func (l *Logger) InfoContext(ctx context.Context, msg string, args ...any) {
	l.Logger.InfoContext(ctx, msg, args...)
}

// WarnContext logs a warning message with context
func (l *Logger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.Logger.WarnContext(ctx, msg, args...)
}

// ErrorContext logs an error message with context
func (l *Logger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l.Logger.ErrorContext(ctx, msg, args...)
}

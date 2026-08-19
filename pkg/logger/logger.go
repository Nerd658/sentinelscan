package logger

import (
	"log/slog"
	"os"
	"strings"
)

var Log *slog.Logger

func Init(levelStr string) {
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	Log = slog.New(handler)
	slog.SetDefault(Log)
}

func Info(msg string, args ...any) {
	if Log == nil {
		Init("info")
	}
	Log.Info(msg, args...)
}

func Error(msg string, args ...any) {
	if Log == nil {
		Init("info")
	}
	Log.Error(msg, args...)
}

func Warn(msg string, args ...any) {
	if Log == nil {
		Init("info")
	}
	Log.Warn(msg, args...)
}

func Debug(msg string, args ...any) {
	if Log == nil {
		Init("info")
	}
	Log.Debug(msg, args...)
}

package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func New() *zap.SugaredLogger {
	cfg := zap.NewProductionConfig()
	level := os.Getenv("LOG_LEVEL")
	if level == "debug" {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	l, _ := cfg.Build()
	return l.Sugar()
}

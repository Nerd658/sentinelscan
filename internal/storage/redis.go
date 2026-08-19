package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"sentinelscan/pkg/config"
	"sentinelscan/pkg/logger"
)

type RedisClient struct {
	Client *redis.Client
}

func NewRedisClient(cfg config.RedisConfig) (*RedisClient, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping redis server at %s: %w", cfg.Address, err)
	}

	logger.Info("Connected to Redis", "addr", cfg.Address, "db", cfg.DB)
	return &RedisClient{Client: rdb}, nil
}

func (r *RedisClient) Close() error {
	if r.Client != nil {
		return r.Client.Close()
	}
	return nil
}

package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/go-redis/redis/v8"
	"github.com/pborman/uuid"
)

var bgCtx = context.Background()

type CacheStore interface {
	AddNonce(nonce string, val string) error
	GetAndDeleteNonce(nonce string) (string, error)
	Clear() error // used in tests only
}

type MemoryStore struct {
	Mutex *sync.Mutex
	Cache *lru.Cache
}

func (store *MemoryStore) AddNonce(nonce string, val string) error {
	store.Mutex.Lock()
	store.Cache.Add(nonce, val)
	store.Mutex.Unlock()
	return nil
}

func (store *MemoryStore) GetAndDeleteNonce(nonce string) (val string, err error) {
	store.Mutex.Lock()
	_val, ok := store.Cache.Get(nonce)
	store.Mutex.Unlock()
	if !ok {
		err = fmt.Errorf("[%T] nonce not found: %s", store, nonce)
		return "", err
	}
	val = _val.(string)
	store.Mutex.Lock()
	store.Cache.Remove(nonce)
	store.Mutex.Unlock()
	return val, nil
}

// used in tests only
func (store *MemoryStore) Clear() error {
	store.Mutex.Lock()
	store.Cache.Clear()
	store.Mutex.Unlock()
	return nil
}

type RedisStore struct {
	Redis *redis.Client
	Namespace string
}

func (store *RedisStore) AddNonce(nonce string, val string) error {
	err := store.Redis.SetEX(bgCtx, store.Prefix(nonce), val, 600 * time.Second).Err()
	if err != nil {
		return err
	}
	return nil
}

func (store *RedisStore) GetAndDeleteNonce(nonce string) (val string, err error) {
	prefixedKey := store.Prefix(nonce)
	val, err = store.Redis.Get(bgCtx, prefixedKey).Result()
	if err != nil {
		return "", fmt.Errorf("[%T] nonce not found: %s", store, nonce)
	}
	err = store.Redis.Del(bgCtx, prefixedKey).Err()
	if err != nil {
		return "", err
	}
	return val, nil
}

// used in tests only
func (store *RedisStore) Clear() error {
	keys, err := store.Redis.Keys(bgCtx, store.Namespace + "*").Result()
	if err != nil {
		return err
	}
	for _, key := range keys {
		err := store.Redis.Del(bgCtx, key).Err()
		if err != nil {
			return err
		}
	}
	return nil
}

func (store *RedisStore) Prefix(in string) string {
	return store.Namespace + in
}

func (store *RedisStore) GetSetNXCookieSecret() (string, error) {
	prefixedKey := store.Prefix("cookie-secret-uuid")
	secret := uuid.New()
	ourSecretSet, err := store.Redis.SetNX(bgCtx, prefixedKey, secret, 0).Result()
	if err != nil {
		return "", err
	}
	if ourSecretSet {
		return secret, nil
	}

	secret, err = store.Redis.Get(bgCtx, prefixedKey).Result()
	if err != nil {
		return "", err
	}
	return secret, nil
}

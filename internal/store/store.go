package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pluginrt "github.com/RXWatcher/silo-plugin-oidc-login/internal/runtime"
)

// ErrReplay is returned by ConsumeNonce when the nonce has already been used
// (or is being used concurrently). ExchangeCode treats it as a replayed
// callback and refuses the login.
var ErrReplay = errors.New("nonce already consumed")

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS app_config (
	id INTEGER PRIMARY KEY DEFAULT 1,
	data JSONB NOT NULL DEFAULT '{}'::jsonb,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT app_config_singleton CHECK (id = 1)
);
INSERT INTO app_config (id, data) VALUES (1, '{}'::jsonb) ON CONFLICT (id) DO NOTHING;

-- auth_nonce backs one-time replay protection for ExchangeCode. Each login
-- flow stashes a unique nonce in provider_state; ConsumeNonce inserts the
-- nonce on first use and fails on any replay. Rows self-expire via expires_at
-- and are swept opportunistically. The nonce is the natural single-use token
-- already minted per flow, so we key on its hash (never the raw value).
CREATE TABLE IF NOT EXISTS auth_nonce (
	nonce_hash BYTEA PRIMARY KEY,
	expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_nonce_expires_at_idx ON auth_nonce (expires_at);
`)
	return err
}

func DefaultConfig() pluginrt.Config {
	return pluginrt.Config{
		Scopes:                "openid profile email",
		DisplayName:           "Sign in with OIDC",
		IconURLPath:           "generic-key.svg",
		EmailVerifiedRequired: true,
	}
}

func (s *Store) GetConfig(ctx context.Context) (pluginrt.Config, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT data FROM app_config WHERE id = 1`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := s.pool.Exec(ctx, `INSERT INTO app_config (id, data) VALUES (1, '{}'::jsonb) ON CONFLICT (id) DO NOTHING`); err != nil {
			return pluginrt.Config{}, fmt.Errorf("ensure app_config: %w", err)
		}
		return s.GetConfig(ctx)
	}
	if err != nil {
		return pluginrt.Config{}, fmt.Errorf("get app_config: %w", err)
	}
	cfg := DefaultConfig()
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return pluginrt.Config{}, fmt.Errorf("decode app_config: %w", err)
		}
	}
	return cfg, nil
}

func (s *Store) UpdateConfig(ctx context.Context, cfg pluginrt.Config) error {
	if err := pluginrt.ValidateConfig(cfg); err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode app_config: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO app_config (id, data, updated_at) VALUES (1, $1, NOW())
		ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
	`, raw)
	if err != nil {
		return fmt.Errorf("update app_config: %w", err)
	}
	return nil
}

// ConsumeNonce atomically records nonce as used, returning ErrReplay if it was
// already recorded. It is the one-time guard that stops a captured OIDC
// callback from being replayed against ExchangeCode: the first call wins, every
// subsequent call with the same nonce is rejected. expiresAt bounds how long
// the row is retained; expired rows are pruned opportunistically so a replay
// arriving after the TTL is still caught by the stale-state check upstream
// (the nonce row is gone, but the state's issued-at timestamp is already too
// old to accept).
//
// The raw nonce is never stored; only its SHA-256 hash is persisted.
func (s *Store) ConsumeNonce(ctx context.Context, nonce string, expiresAt time.Time) error {
	if nonce == "" {
		return errors.New("empty nonce")
	}
	sum := sha256.Sum256([]byte(nonce))

	// Opportunistic prune of expired rows keeps the table bounded without a
	// separate sweeper. Best-effort: a failure here must not block the insert.
	_, _ = s.pool.Exec(ctx, `DELETE FROM auth_nonce WHERE expires_at < NOW()`)

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO auth_nonce (nonce_hash, expires_at) VALUES ($1, $2)
		ON CONFLICT (nonce_hash) DO NOTHING
	`, sum[:], expiresAt)
	if err != nil {
		return fmt.Errorf("consume nonce: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrReplay
	}
	return nil
}

func (s *Store) ImportLegacyConfig(ctx context.Context, legacy pluginrt.Config) (pluginrt.Config, error) {
	current, err := s.GetConfig(ctx)
	if err != nil {
		return pluginrt.Config{}, err
	}
	if !reflect.DeepEqual(current, DefaultConfig()) {
		return current, nil
	}
	legacy.DatabaseURL = ""
	if reflect.DeepEqual(legacy, current) {
		return current, nil
	}
	if err := s.UpdateConfig(ctx, legacy); err != nil {
		return pluginrt.Config{}, err
	}
	return s.GetConfig(ctx)
}

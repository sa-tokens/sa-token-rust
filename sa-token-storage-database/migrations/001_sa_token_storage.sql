-- Sa-Token 通用 KV 存储（PostgreSQL）
CREATE TABLE IF NOT EXISTS sa_token_storage (
    key         VARCHAR(512) PRIMARY KEY,
    value       TEXT NOT NULL,
    expire_at   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sa_token_storage_expire_at
    ON sa_token_storage (expire_at)
    WHERE expire_at IS NOT NULL;

COMMENT ON TABLE sa_token_storage IS 'Sa-Token 通用 KV 存储';
COMMENT ON COLUMN sa_token_storage.key IS '逻辑键（含 sa: 前缀）';
COMMENT ON COLUMN sa_token_storage.expire_at IS '过期时刻，NULL 表示永不过期';

-- MySQL >8.0 变体（需手动执行）:
-- CREATE TABLE sa_token_storage (
--     `key`       VARCHAR(512) PRIMARY KEY,
--     `value`     TEXT NOT NULL,
--     expire_at   DATETIME(6) NULL,
--     created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
--     updated_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
--     INDEX idx_sa_token_storage_expire_at (expire_at)
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

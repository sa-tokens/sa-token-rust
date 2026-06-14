#!/usr/bin/env bash

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SLEEP_SECONDS="${SLEEP_SECONDS:-5}"
VERIFY="${VERIFY:-1}" # 1=发布前执行一次 workspace 校验，0=跳过
SKIP_PUBLISHED="${SKIP_PUBLISHED:-1}" # 1=已发布版本自动跳过，0=遇到已发布直接失败

publish() {
  local manifest="$1"
  local output

  echo "Publishing ${manifest}..."
  if output="$(cargo publish --manifest-path "$manifest" 2>&1)"; then
    echo "$output"
  else
    echo "$output"
    if [[ "$SKIP_PUBLISHED" == "1" ]] && [[ "$output" == *"already exists on crates.io index"* ]]; then
      echo "Skip published crate: ${manifest}"
      return 0
    fi
    echo "Publish failed: ${manifest}"
    return 1
  fi

  echo "Waiting ${SLEEP_SECONDS}s for crates.io index to update..."
  sleep "${SLEEP_SECONDS}"
}

if [[ "$VERIFY" == "1" ]]; then
  echo "Running pre-publish checks..."
  cargo check --workspace --manifest-path "$WORKSPACE_ROOT/Cargo.toml"
fi

# 发布顺序：先基础库，再版本绑定插件，最后 facade 与根包
publish "$WORKSPACE_ROOT/sa-token-adapter/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-storage-memory/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-storage-redis/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-core/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-macro/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-storage-database/Cargo.toml"
# 一体化插件
publish "$WORKSPACE_ROOT/sa-token-plugin-axum/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-poem/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-tide/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-warp/Cargo.toml"

# Actix（core -> v* -> facade）
publish "$WORKSPACE_ROOT/sa-token-plugin-actix-web-core/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-actix-web-v4/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-actix-web-v5/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-actix-web/Cargo.toml"

# Rocket（core -> v* -> facade）
publish "$WORKSPACE_ROOT/sa-token-plugin-rocket-core/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-rocket-v05/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-rocket/Cargo.toml"

# Salvo（core -> v* -> facade）
publish "$WORKSPACE_ROOT/sa-token-plugin-salvo-core/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-salvo-v079/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-salvo/Cargo.toml"

# Gotham（core -> v* -> facade）
publish "$WORKSPACE_ROOT/sa-token-plugin-gotham-core/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-gotham-v074/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-gotham/Cargo.toml"

# Ntex（core -> v* -> facade）
publish "$WORKSPACE_ROOT/sa-token-plugin-ntex-core/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-ntex-v212/Cargo.toml"
publish "$WORKSPACE_ROOT/sa-token-plugin-ntex/Cargo.toml"

# 根包
publish "$WORKSPACE_ROOT/Cargo.toml"

echo "All crates published."


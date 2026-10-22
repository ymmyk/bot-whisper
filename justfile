# BotWhisper dev + deploy commands. `just` lists recipes.

_sdk := "/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk"
export SDKROOT := if os() == "macos" { if path_exists(_sdk) == "true" { _sdk } else { env_var_or_default("SDKROOT", "") } } else { env_var_or_default("SDKROOT", "") }
export PATH := "/opt/homebrew/opt/rustup/bin:" + env_var("HOME") + "/.cargo/bin:/opt/homebrew/bin:" + env_var("PATH")

prod_ssh := "ubuntu@100.76.139.125"

default:
    @just --list

# Build the workspace (release)
build:
    cargo build --release

# Run all tests
test:
    cargo test --workspace

# fmt check + clippy with warnings as errors
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

# Format the code
fmt:
    cargo fmt --all

# Lint + test (run before every deploy)
check: lint test

# Run the relay on 0.0.0.0:9100 (tokens from BW_DEV_TOKENS or generated)
run *args:
    cargo run -p bw-cli -- relay --bind 0.0.0.0:9100 {{args}}

# Serve the homepage from ./site on 0.0.0.0:9102
site:
    python3 -m http.server 9102 --bind 0.0.0.0 --directory site

# Package HEAD as the source tarball the playbook builds on the server
_src:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
      echo "warning: uncommitted changes are NOT deployed (deploy uses git HEAD $(git rev-parse --short HEAD))"
    fi
    mkdir -p target/deploy
    git archive --format=tar HEAD | gzip -n > target/deploy/botwhisper-src.tar.gz.new
    if cmp -s target/deploy/botwhisper-src.tar.gz.new target/deploy/botwhisper-src.tar.gz; then
      rm target/deploy/botwhisper-src.tar.gz.new
    else
      mv target/deploy/botwhisper-src.tar.gz.new target/deploy/botwhisper-src.tar.gz
    fi

# Deploy to production (asks for confirmation)
deploy: _src
    #!/usr/bin/env bash
    set -euo pipefail
    read -r -p "Deploy $(git rev-parse --short HEAD) to PRODUCTION? [y/N] " ok
    [ "$ok" = "y" ] || [ "$ok" = "Y" ] || { echo "aborted"; exit 1; }
    cd ansible && ansible-playbook site.yml

# Dry run against production (--check --diff)
deploy-check: _src
    cd ansible && ansible-playbook site.yml --check --diff

# Push deploy/botwhisper.caddy to ~/caddy on prod and reload via arbiter's `just caddy-reload`
caddy-push:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "validating snippet in the Caddy container..."
    ssh {{prod_ssh}} 'docker exec -i arbiter-caddy sh -c "cat > /tmp/botwhisper-candidate.caddy && caddy validate --adapter caddyfile --config /tmp/botwhisper-candidate.caddy; rc=\$?; rm -f /tmp/botwhisper-candidate.caddy; exit \$rc"' < deploy/botwhisper.caddy >/dev/null
    scp -q deploy/botwhisper.caddy {{prod_ssh}}:caddy/botwhisper.caddy.new
    ssh {{prod_ssh}} 'set -e; cd ~/caddy; [ -f botwhisper.caddy ] && cp -p botwhisper.caddy ~/.botwhisper.caddy.prev || true; mv botwhisper.caddy.new botwhisper.caddy; chmod 644 botwhisper.caddy
      if ! docker exec arbiter-caddy caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
        echo "full config invalid, rolling back"; if [ -f ~/.botwhisper.caddy.prev ]; then mv ~/.botwhisper.caddy.prev botwhisper.caddy; else rm -f botwhisper.caddy; fi; exit 1; fi
      cd ~/arbiter && just caddy-reload'

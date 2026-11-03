#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
base_commit=$(git rev-parse HEAD)
staged_tree=$(git write-tree)
staged_paths=$(git diff --cached --name-only --diff-filter=ACDMR)
if [[ -z "$staged_paths" ]]; then
  exit 0
fi
check_go=false
check_rust=false
check_protocol=false
if grep -Eq '^(concentrator/|sna/|proto/|sna_router/crates/snusnu-router/Cargo\.toml$|docs/protocol\.md$|docs/test-vectors/|\.github/workflows/go\.yml$|\.githooks/|scripts/pre-commit-check\.sh$)' <<< "$staged_paths"; then
  check_go=true
fi
if grep -Eq '^(sna_router/|proto/|docs/protocol\.md$|docs/test-vectors/|\.github/workflows/rust\.yml$|\.githooks/|scripts/pre-commit-check\.sh$)' <<< "$staged_paths"; then
  check_rust=true
fi
if grep -Eq '^(docs/protocol\.md$|docs/test-vectors/|\.github/workflows/protocol\.yml$|\.githooks/|scripts/pre-commit-check\.sh$)' <<< "$staged_paths"; then
  check_protocol=true
fi
if ! $check_go && ! $check_rust && ! $check_protocol; then
  exit 0
fi
check_dir=$(mktemp -d "${TMPDIR:-/tmp}/snusnu-precommit.XXXXXXXX")
trap 'rm -rf "$check_dir"' EXIT

# CI checks the committed tree. Build the staged tree so concurrent or
# unrelated worktree edits cannot make a commit appear to pass or fail.
# Keep the checkout path stable for Cargo's incremental cache. Serialize checks
# in this worktree because they also share its checkout and target directory.
check_state="$repo_root/sna_router/target"
mkdir -p "$check_state"
exec {check_lock_fd}> "$check_state/precommit.lock"
flock "$check_lock_fd"
check_tree="$check_state/precommit-tree"
git diff --cached --binary "$base_commit" > "$check_dir/staged.patch"
if [[ ! -d "$check_tree/.git" ]]; then
  env -u GIT_INDEX_FILE git clone --quiet --local --shared --no-checkout "$repo_root" "$check_tree"
fi
env -u GIT_INDEX_FILE git -C "$check_tree" checkout --quiet --detach --force "$base_commit"
env -u GIT_INDEX_FILE git -C "$check_tree" clean --quiet -fdx
if [[ -s "$check_dir/staged.patch" ]]; then
  env -u GIT_INDEX_FILE git -C "$check_tree" apply --index "$check_dir/staged.patch"
fi
if [[ $(env -u GIT_INDEX_FILE git -C "$check_tree" write-tree) != "$staged_tree" ]]; then
  echo "pre-commit: staged checkout does not match index" >&2
  exit 1
fi

check_go_module() {
  local module=$1
  echo "pre-commit: $module formatting, vet, tests, build"
  (
    cd "$check_tree/$module"
    go_version=$(awk '$1 == "go" { print $2; exit }' "$check_tree/concentrator/go.mod")
    export GOTOOLCHAIN="go${go_version}+auto"
    go_toolchain_root=$(go env GOROOT)
    unformatted=$("$go_toolchain_root/bin/gofmt" -l .)
    if [[ -n "$unformatted" ]]; then
      printf 'Go files need gofmt:\n%s\n' "$unformatted" >&2
      exit 1
    fi
    go vet ./...
    go test ./...
    go build ./...
  )
}

if $check_go; then
  check_go_module concentrator
  check_go_module sna
fi

if $check_rust; then
  echo "pre-commit: Rust formatting, clippy, tests, build"
  (
    cd "$check_tree/sna_router"
    export CARGO_TARGET_DIR="$repo_root/sna_router/target/precommit"
    cargo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo build --workspace --all-targets
  )
fi

if $check_protocol; then
  echo "pre-commit: protocol documentation gate"
  test -f "$check_tree/docs/protocol.md"
  test -d "$check_tree/docs/test-vectors"
  test -f "$check_tree/docs/test-vectors/README.md"
  grep -q '## Implemented invariants' "$check_tree/docs/protocol.md"
  grep -q '## Captured vectors' "$check_tree/docs/test-vectors/README.md"
fi

# Another worker can stage files while this hook runs. Git commits the index
# as it exists after the hook, so reject a changed index rather than approving
# a different tree from the one tested above.
if [[ $(git rev-parse HEAD) != "$base_commit" || $(git write-tree) != "$staged_tree" ]]; then
  echo "pre-commit: HEAD or staged tree changed during checks; retry the commit" >&2
  exit 1
fi

echo "pre-commit: all CI checks passed"

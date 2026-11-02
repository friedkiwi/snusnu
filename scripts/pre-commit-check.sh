#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
base_commit=$(git rev-parse HEAD)
staged_paths=$(git diff --cached --name-only --diff-filter=ACDMR)
if [[ -z "$staged_paths" ]]; then
  exit 0
fi
check_go=false
check_rust=false
check_protocol=false
if grep -Eq '^(concentrator/|sna/|docs/protocol\.md$|docs/test-vectors/|\.github/workflows/go\.yml$)' <<< "$staged_paths"; then
  check_go=true
fi
if grep -Eq '^(sna_router/|docs/protocol\.md$|docs/test-vectors/|\.github/workflows/rust\.yml$)' <<< "$staged_paths"; then
  check_rust=true
fi
if grep -Eq '^(docs/protocol\.md$|docs/test-vectors/|\.github/workflows/protocol\.yml$)' <<< "$staged_paths"; then
  check_protocol=true
fi
if ! $check_go && ! $check_rust && ! $check_protocol; then
  exit 0
fi
check_dir=$(mktemp -d "${TMPDIR:-/tmp}/snusnu-precommit.XXXXXXXX")
trap 'rm -rf "$check_dir"' EXIT

# CI checks the committed tree. Build the staged tree so concurrent or
# unrelated worktree edits cannot make a commit appear to pass or fail.
git diff --cached --binary "$base_commit" > "$check_dir/staged.patch"
git clone --quiet --local --shared --no-checkout "$repo_root" "$check_dir/tree"
git -C "$check_dir/tree" checkout --quiet "$base_commit"
if [[ -s "$check_dir/staged.patch" ]]; then
  git -C "$check_dir/tree" apply --index "$check_dir/staged.patch"
fi

check_go_module() {
  local module=$1
  echo "pre-commit: $module formatting, vet, tests, build"
  (
    cd "$check_dir/tree/$module"
    unformatted=$(gofmt -l .)
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
    cd "$check_dir/tree/sna_router"
    export CARGO_TARGET_DIR="$repo_root/sna_router/target/precommit"
    cargo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo build --workspace --all-targets
  )
fi

if $check_protocol; then
  echo "pre-commit: protocol documentation gate"
  test -f "$check_dir/tree/docs/protocol.md"
  test -d "$check_dir/tree/docs/test-vectors"
  test -f "$check_dir/tree/docs/test-vectors/README.md"
  grep -q 'No vectors are invented before the layout is defined' "$check_dir/tree/docs/test-vectors/README.md"
fi

echo "pre-commit: all CI checks passed"

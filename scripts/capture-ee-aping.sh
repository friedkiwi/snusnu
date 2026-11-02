#!/usr/bin/env bash
# Capture the complete TAP while an operator runs one EE APING trial.
# OS/400 emits IPv4 inside 802.3 SNAP frames, so a tcpdump UDP filter misses it.
set -euo pipefail

tap=${1:-sol7}
output_dir=${2:-/tmp/snusnu-ee-aping}
seconds=${3:-180}

if [[ ! $seconds =~ ^[1-9][0-9]*$ ]]; then
    printf 'duration must be a positive number of seconds\n' >&2
    exit 2
fi
if ! ip link show dev "$tap" >/dev/null 2>&1; then
    printf 'TAP interface does not exist: %s\n' "$tap" >&2
    exit 2
fi
mkdir -p "$output_dir"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
capture="$output_dir/${tap}-${stamp}.pcap"
printf 'Capturing unfiltered %s for %s seconds to %s\n' "$tap" "$seconds" "$capture" >&2
exec timeout --preserve-status --signal=INT "$seconds" sudo -n tcpdump -i "$tap" -s 0 -U -w "$capture"

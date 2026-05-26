#!/usr/bin/env bash
# .NET 反编译（ilspycmd，macOS / Linux）
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <input.dll> <output_dir>" >&2
  exit 1
fi

INPUT="$1"
OUTDIR="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/ensure-env.sh
source "${SCRIPT_DIR}/../lib/ensure-env.sh"

ILSPY="$(resolve_ilspycmd)" || {
  echo "ERROR: ilspycmd unavailable after auto-setup" >&2
  exit 1
}

if [[ ! -f "$INPUT" ]]; then
  echo "ERROR: input not found: $INPUT" >&2
  exit 1
fi

mkdir -p "$OUTDIR"
"$ILSPY" "$INPUT" -p -o "$OUTDIR"
echo "Decompiled to: $OUTDIR"

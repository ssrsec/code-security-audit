#!/usr/bin/env bash
# Java 反编译（CFR，macOS / Linux）
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <input.jar|.class|.war> <output_dir>" >&2
  exit 1
fi

INPUT="$1"
OUTDIR="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/ensure-env.sh
source "${SCRIPT_DIR}/../lib/ensure-env.sh"
ensure_java

CFR_JAR="${DECOMP_ROOT}/java/cfr-0.152.jar"
if [[ ! -f "$CFR_JAR" ]]; then
  echo "ERROR: CFR not found at $CFR_JAR" >&2
  exit 1
fi
if [[ ! -e "$INPUT" ]]; then
  echo "ERROR: input not found: $INPUT" >&2
  exit 1
fi

mkdir -p "$OUTDIR"
case "$INPUT" in
  *.jar|*.war|*.ear|*.zip|*.class)
    java -jar "$CFR_JAR" "$INPUT" --outputdir "$OUTDIR" --silent true
    ;;
  *)
    echo "ERROR: unsupported input type: $INPUT" >&2
    exit 1
    ;;
esac
echo "Decompiled to: $OUTDIR"

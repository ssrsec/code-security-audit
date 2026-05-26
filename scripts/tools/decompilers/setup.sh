#!/usr/bin/env bash
# 显式初始化：检测环境并安装全部反编译依赖
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/lib/ensure-env.sh" all

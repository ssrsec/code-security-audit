#!/usr/bin/env bash
# 检测运行环境并按需自动安装反编译依赖（供 bin/*.sh 调用）
set -euo pipefail

DECOMP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOTNET_TOOL_PATH="${DECOMP_ROOT}/dotnet"
ILSPY_VERSION="9.1.0.7988"
AUTO_INSTALL="${DECOMPILERS_AUTO_INSTALL:-1}"

detect_os() {
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Darwin)  echo "macos" ;;
    Linux)   echo "linux" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *)       echo "unknown" ;;
  esac
}

log() { echo "[decompilers] $*" >&2; }

try_java_from_macos_java_home() {
  if [[ -x /usr/libexec/java_home ]]; then
    local jh
    jh="$(/usr/libexec/java_home 2>/dev/null || true)"
    if [[ -n "$jh" && -x "$jh/bin/java" ]]; then
      export JAVA_HOME="$jh"
      export PATH="$jh/bin:$PATH"
      return 0
    fi
  fi
  return 1
}

install_java() {
  local os
  os="$(detect_os)"
  log "未检测到 java，尝试自动安装（DECOMPILERS_AUTO_INSTALL=${AUTO_INSTALL}）..."

  case "$os" in
    macos)
      if command -v brew >/dev/null 2>&1; then
        brew install --cask temurin
        try_java_from_macos_java_home || true
        command -v java >/dev/null 2>&1 && return 0
      fi
      ;;
    linux)
      if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
        sudo apt-get install -y default-jre-headless
        command -v java >/dev/null 2>&1 && return 0
      fi
      if command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y java-17-openjdk-headless
        command -v java >/dev/null 2>&1 && return 0
      fi
      ;;
    windows)
      if command -v winget >/dev/null 2>&1; then
        winget install -e --id EclipseAdoptium.Temurin.17.JRE \
          --accept-package-agreements --accept-source-agreements
        command -v java >/dev/null 2>&1 && return 0
      fi
      ;;
  esac
  return 1
}

ensure_java() {
  if command -v java >/dev/null 2>&1; then
    return 0
  fi
  try_java_from_macos_java_home && command -v java >/dev/null 2>&1 && return 0

  if [[ "$AUTO_INSTALL" != "1" ]]; then
    log "ERROR: 未找到 java。请安装 JRE 8+，或设置 DECOMPILERS_AUTO_INSTALL=1 后重试。"
    return 1
  fi
  install_java || {
    log "ERROR: 无法自动安装 Java。请手动安装 JRE 8+：https://adoptium.net/"
    return 1
  }
}

install_dotnet_sdk() {
  local os
  os="$(detect_os)"
  log "未检测到 dotnet，尝试自动安装 SDK..."

  case "$os" in
    macos)
      if command -v brew >/dev/null 2>&1; then
        brew install dotnet
        return 0
      fi
      ;;
    linux)
      if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
        sudo apt-get install -y dotnet-sdk-8.0 || sudo apt-get install -y dotnet-sdk-9.0
        return 0
      fi
      ;;
    windows)
      if command -v winget >/dev/null 2>&1; then
        winget install -e --id Microsoft.DotNet.SDK.8 \
          --accept-package-agreements --accept-source-agreements
        return 0
      fi
      ;;
  esac
  return 1
}

install_ilspycmd() {
  if ! command -v dotnet >/dev/null 2>&1; then
    if [[ "$AUTO_INSTALL" == "1" ]]; then
      install_dotnet_sdk || true
    fi
  fi
  if ! command -v dotnet >/dev/null 2>&1; then
    log "ERROR: 未找到 dotnet。请安装 .NET SDK 8+：https://dotnet.microsoft.com/download"
    return 1
  fi

  mkdir -p "$DOTNET_TOOL_PATH"
  log "安装/更新 ilspycmd ${ILSPY_VERSION} 到 ${DOTNET_TOOL_PATH} ..."
  if dotnet tool install ilspycmd --version "$ILSPY_VERSION" --tool-path "$DOTNET_TOOL_PATH" 2>/dev/null; then
    :
  else
    dotnet tool update ilspycmd --version "$ILSPY_VERSION" --tool-path "$DOTNET_TOOL_PATH"
  fi
}

ilspycmd_works() {
  local bin="$1"
  [[ -n "$bin" && -x "$bin" ]] && "$bin" --help >/dev/null 2>&1
}

resolve_ilspycmd() {
  local bundled="${DOTNET_TOOL_PATH}/ilspycmd"
  if ilspycmd_works "$bundled"; then
    echo "$bundled"
    return 0
  fi
  # 仓库内二进制可能为其他平台，删除后重装
  if [[ -e "$bundled" ]] && ! ilspycmd_works "$bundled"; then
    log "内置 ilspycmd 与当前平台不匹配，将重新安装..."
    rm -f "$bundled" "${DOTNET_TOOL_PATH}/ilspycmd.exe" 2>/dev/null || true
  fi
  if [[ "$AUTO_INSTALL" == "1" ]]; then
    install_ilspycmd
    ilspycmd_works "$bundled" && { echo "$bundled"; return 0; }
  fi
  if command -v ilspycmd >/dev/null 2>&1 && ilspycmd_works "$(command -v ilspycmd)"; then
    command -v ilspycmd
    return 0
  fi
  return 1
}

ensure_dotnet() {
  resolve_ilspycmd >/dev/null
}

# 直接执行: ensure-env.sh [java|dotnet|all] ；被 source 时仅加载函数
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  mode="${1:-all}"
  case "$mode" in
    java)   ensure_java ;;
    dotnet) ensure_dotnet ;;
    all)
      ensure_java
      ensure_dotnet
      ;;
    *)
      echo "Usage: $0 [java|dotnet|all]" >&2
      exit 1
      ;;
  esac
fi

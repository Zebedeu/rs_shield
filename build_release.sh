#!/bin/bash
set -e

echo "🚀 Iniciando Build Release para o sistema atual..."

# 1. Compilar todo o workspace (CLI + Core + Desktop)
cargo build --release --workspace

# 2. Criar pasta de distribuição
DIST_DIR="dist/local"
mkdir -p "$DIST_DIR"

# 3. Copiar binários
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🐧 Empacotando para Linux..."
    cp target/release/rsb-cli "$DIST_DIR/"
    cp target/release/rsb-desktop "$DIST_DIR/"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍎 Empacotando para macOS..."
    cp target/release/rsb-cli "$DIST_DIR/"
    cp target/release/rsb-desktop "$DIST_DIR/"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "🪟 Empacotando para Windows..."
    cp target/release/rsb-cli.exe "$DIST_DIR/"
    cp target/release/rsb-desktop.exe "$DIST_DIR/"
fi

echo "✅ Build concluído! Binários disponíveis em: $DIST_DIR"
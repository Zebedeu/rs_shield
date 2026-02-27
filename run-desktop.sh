#!/bin/bash
# RSB Desktop Launcher Script

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# Check if release binary exists
if [ ! -f "target/release/rsb-desktop" ]; then
    echo "📦 Building RSB Desktop in release mode..."
    cargo build -p rsb-desktop --release
fi

echo "🚀 Launching RSB Desktop..."
./target/release/rsb-desktop

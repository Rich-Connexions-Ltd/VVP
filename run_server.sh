#!/bin/bash
# VVP Development Server Startup Script
# Sets library paths required for pysodium/libsodium

# Homebrew libsodium location (Apple Silicon)
export DYLD_LIBRARY_PATH="/opt/homebrew/lib:$DYLD_LIBRARY_PATH"

# Start uvicorn with hot reload
exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload "$@"

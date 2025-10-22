#!/bin/bash

BASE_URL="$1"
DEPTH="${2:-2}"  # Default depth of 2

if [ -z "$BASE_URL" ]; then
    echo "Usage: $0 <base_url> [depth]"
    echo "Example: $0 http://127.0.0.1 2"
    exit 1
fi

echo "=== Recursive Fuzzing ==="
echo "Base URL: $BASE_URL"
echo "Depth: $DEPTH"
echo

# Function to fuzz a directory
fuzz_dir() {
    local url="$1"
    local current_depth="$2"
    
    echo
    echo "[$current_depth] Fuzzing: $url"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Run fuzzer and capture results
    RESULTS=$(cargo run --release -- fuzz \
        --url "$url" \
        --mode dir \
        --concurrent 10 \
        --status-filter "200,301,302" 2>&1 | grep -E "✅|↗️")
    
    echo "$RESULTS"
    
    # If we haven't reached max depth, recurse into found directories
    if [ "$current_depth" -lt "$DEPTH" ]; then
        # Extract URLs with 200 or 301 status
        FOUND_DIRS=$(echo "$RESULTS" | grep -oP 'http://[^ ]+' | grep -v "\.php$" | grep -v "\.html$")
        
        for dir in $FOUND_DIRS; do
            fuzz_dir "$dir" $((current_depth + 1))
        done
    fi
}

# Start fuzzing
fuzz_dir "$BASE_URL" 1

echo
echo "=== Recursive Fuzzing Complete ==="

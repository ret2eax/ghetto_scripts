# Basic SH script to search insecurities associated with iOS IPA binary build
#!/bin/sh
#
# Color codes for formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo " "
echo -e "${BLUE}[ oTool Enumeration Script for iOS IPA Binary Analysis (Minimal Checks) ]${RED}"
echo "Requires oTool: DL from CC Darwin Tools in Cydia"
echo " "
echo -n -e "${YELLOW}Enter binary path (e.g., /private/var/containers/Bundle/Application/89D9BDB1-9803-4446-B3FF-BF3CEBB6471A/example.app/example): ${NC}"
echo ""
read -r binaryPath
echo " "
echo "Binary path set to: $binaryPath"
echo " "
echo -e "${GREEN}SEARCHING FOR INSECURE RNGs...${RED}"
echo " "
otool -Iv "$binaryPath" | grep -w _random
otool -Iv "$binaryPath" | grep -w _srand
otool -Iv "$binaryPath" | grep -w _rand
echo " "
echo -e "${BLUE}_________________________________________${NC}"
echo " "
echo -e "${GREEN}SEARCHING FOR WEAK HASHING ALGORITHMS...${RED}"
echo " "
# HASHING:
otool -Iv "$binaryPath" | grep -w _CC_MD5
otool -Iv "$binaryPath" | grep -w _CC_SHA1
echo " "
echo -e "${BLUE}_________________________________________${NC}"
echo " "
echo -e "${GREEN}SEARCHING FOR INSECURE & DEPRECATED API FUNCTIONS...${RED}"
echo ""
# Deprecated Functions:
deprecated_functions=("memcpy" "strncpy" "strcpy" "strlen" "strcat" "strncat" "sprintf" "vsprintf" "gets")
for func in "${deprecated_functions[@]}"; do
    otool -Iv "$binaryPath" | grep -w "_$func"
done
echo " "
echo -e "${BLUE}_________________________________________${NC}"
echo " "
echo -e "${GREEN}SEARCHING FOR BINARY PROTECTION...${RED}"
echo " "
echo -e "${BLUE}ASLR:${RED}"
otool -Vh "$binaryPath" | grep PIE
echo ""
echo -e "${BLUE}ARC:${RED}"
otool -Iv "$binaryPath" | grep -w _objc_release
echo ""
echo -e "${BLUE}Stack smashing:${RED}"
otool -Iv "$binaryPath" | grep -w ___stack_chk_guard
echo " "
echo -e "${GREEN}Done.${NC}"
echo " "

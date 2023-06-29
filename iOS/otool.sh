# Basic Static Analysis SH script to search insecurities associated with iOS IPA binary build.

# USAGE
# 1. Install Darwin CC Tools on JB device
# 2. Save the script as otool.sh
# 3. chmod +x otool.sh
#4. ./otool.sh

#!/bin/sh
#
# Color codes for formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
#BEGIN
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
echo -e "${BLUE}[ INSECURE RNGs ]${RED}"
echo " "
otool -Iv "$binaryPath" | grep -w _random
otool -Iv "$binaryPath" | grep -w _srand
otool -Iv "$binaryPath" | grep -w _rand
echo ""
echo -e "${BLUE}_________________________________________${NC}"
echo " "
echo -e "${BLUE}[ INSECURE 'MALLOC' FUNCTION ]${RED}"
echo " "
otool -Iv "$binaryPath"  | grep -w "_malloc"
echo " "
echo -e "${BLUE}_________________________________________${NC}"
echo " "
echo -e "${BLUE}[ WEAK HASHING ALGORITHMS ]${RED}"
echo " "
otool -Iv "$binaryPath" | grep -w _CC_MD5
otool -Iv "$binaryPath" | grep -w _CC_SHA1
echo ""
echo -e "${BLUE}_________________________________________${NC}"
echo " "
echo -e "${BLUE}USE OF INSECURE & DEPRECATED APIs ]${RED}"
echo ""
deprecated_functions=("memcpy" "strncpy" "strcpy" "strlen" "strcat" "strncat" "sprintf" "vsprintf" "vsnprintf" "gets" "sscanf" "strtok" "alloca" "printf")
for func in "${deprecated_functions[@]}"; do
    otool -Iv "$binaryPath" | grep -w "_$func"
done
echo " "
echo -e "${BLUE}_________________________________________${NC}"
echo " "
echo -e "${BLUE}[ BINARY PROTECTION MECHANISMS ]${GREEN}"
echo " "
echo -e "${BLUE}PIE (Position Independent Executable): Should include the PIE Flag:${GREEN}"
otool -Vh "$binaryPath" | grep PIE
echo ""
echo -e "${BLUE}ARC (Automatic Reference Counting): Should include the _objc_release symbol:${GREEN}"
otool -Iv "$binaryPath" | grep -w _objc_release
echo ""
echo -e "${BLUE}Encrypted Binary: The binary should be encrypted (only for iOS App Store IPAs): The cryptid should be '1'${GREEN}"
otool -arch all -Vl "$binaryPath" | grep -A5 LC_ENCRYPT
echo " "
echo -e "${BLUE}Stack smashing:${GREEN}"
otool -Iv "$binaryPath" | grep -w ___stack_chk_guard
echo -e "${NC} ${NC}"
#EOF

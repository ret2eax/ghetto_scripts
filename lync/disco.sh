#!/bin/sh
echo ""
echo "Discover Skye4B / Microsoft Lync Installations against a list of domains"
echo "Handy for bug bounties, etc."
echo ""
if [ -f 'domains.txt' ]; then
        while read line; do
                ./lyncsmash.py discover -H $line;
        done < "domains.txt"
fi
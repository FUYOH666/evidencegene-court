#!/usr/bin/env bash
# Fetch DFIR Madness Case 001 evidence (public, with published ground truth).
# The site is behind ModSecurity; browser-like headers are required.
set -euo pipefail

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)/cases/case001"
mkdir -p "$CASE_DIR"
cd "$CASE_DIR"

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
REF="https://dfirmadness.com/the-stolen-szechuan-sauce/"
BASE="https://dfirmadness.com/case001"

# Minimal demo set: memory (correlation), disk (cross-source), pcap (context).
FILES=("${@:-DC01-memory.zip DC01-E01.zip case001-pcap.zip}")

for f in ${FILES[@]}; do
  echo "=== $f ==="
  curl -L -C - -o "$f" \
    -H "User-Agent: $UA" \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    -H "Accept-Language: en-US,en;q=0.9" \
    -H "Referer: $REF" \
    "$BASE/$f"
  echo "DONE $f ($(ls -lh "$f" | awk '{print $5}'))"
done
echo "ALL DONE"

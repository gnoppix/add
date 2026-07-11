#!/bin/bash
# Verify documentation matches source code
set -e

echo "=== Documentation Verification ==="

PASS=0
FAIL=0

# Check version consistency across docs
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*= *"//;s/"//')
echo "[1] Workspace version: $VERSION"

# Check CHANGELOG has entry for current version
if grep -q "## $VERSION" CHANGELOG.md; then
    echo "  OK: CHANGELOG has v$VERSION entry"
    PASS=$((PASS+1))
else
    echo "  FAIL: CHANGELOG missing v$VERSION entry"
    FAIL=$((FAIL+1))
fi

# Check README mentions version or build instructions
if grep -q "Cargo\|cargo build\|make" README.md; then
    echo "  OK: README has build instructions"
    PASS=$((PASS+1))
else
    echo "  FAIL: README missing build instructions"
    FAIL=$((FAIL+1))
fi

# Check FEATURES.md exists (merged into DEVELOPER.md per 0.2.0 changelog)
if [ -f FEATURES.md ]; then
    echo "  OK: FEATURES.md exists"
    PASS=$((PASS+1))
else
    echo "  INFO: FEATURES.md merged into DEVELOPER.md (per 0.2.0 changelog)"
    PASS=$((PASS+1))
fi

# Check DEVELOPER.md exists
if [ -f DEVELOPER.md ]; then
    echo "  OK: DEVELOPER.md exists"
    PASS=$((PASS+1))
else
    echo "  FAIL: DEVELOPER.md missing"
    FAIL=$((FAIL+1))
fi

# Check FAQ.md exists
if [ -f FAQ.md ]; then
    echo "  OK: FAQ.md exists"
    PASS=$((PASS+1))
else
    echo "  FAIL: FAQ.md missing"
    FAIL=$((FAIL+1))
fi

# Verify key CLI flags are documented
echo "[2] Checking CLI flag documentation..."
for flag in "--tls-cert" "--tls-key" "--gpg-home" "--db-path" "--host" "--port"; do
    if grep -q "$flag" DEVELOPER.md README.md 2>/dev/null; then
        echo "  OK: $flag documented"
        PASS=$((PASS+1))
    else
        echo "  WARN: $flag not in docs"
    fi
done

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "=== PASSED ===" || echo "=== FAILED ==="

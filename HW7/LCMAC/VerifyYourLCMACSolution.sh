#!/bin/bash
set -euo pipefail

rm -rf lc_umac ./*.log a*.txt b*.txt tags*.txt aggtag*.txt

gcc lc_umac.c -lcrypto        -o lc_umac

total=0
passed=0
failed=0
failed_list=()

check() {
    local label=$1 got=$2 expected=$3
    total=$(( total + 1 ))
    if cmp -s "$got" "$expected"; then
        echo "  [PASS] ${label}"
        passed=$(( passed + 1 ))
    else
        echo "  [FAIL] ${label}"
        failed=$(( failed + 1 ))
        failed_list+=("$label")
    fi
}

# run_test <i>
run_test() {
    local i=$1

    echo "=== Test${i} ==="

    ./lc_umac   q${i}.txt seed.txt message${i}.txt > lc_umac_${i}.log

    check "a${i}"            "a.txt"             "correct_a${i}.txt"
    check "b${i}"            "b.txt"             "correct_b${i}.txt"
    check "tags${i}"         "tags.txt"          "correct_tags${i}.txt"
    check "aggtag${i}"       "aggtag.txt"        "correct_aggtag${i}.txt"

    echo ""
}

for i in {1..4}; do
  run_test "$i"
done

echo "════════════════════════════════════════"
echo "  Results: ${passed}/${total} passed"
echo "  Failed:  ${failed}/${total}"
if [ ${#failed_list[@]} -gt 0 ]; then
    echo ""
    echo "  Failed checks:"
    for item in "${failed_list[@]}"; do
        echo "    - ${item}"
    done
fi
echo "════════════════════════════════════════"

[ "$failed" -eq 0 ]

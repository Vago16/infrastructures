#!/bin/bash
set -euo pipefail

rm -rf rsa ./*.log individual_rsa.txt condensed_rsa.txt

gcc rsa.c -lcrypto -o rsa

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

    ./rsa   rsa_params.txt message${i}.txt > rsa${i}.log

    check "individual_rsa${i}"        "individual_rsa.txt"        "correct_individual_rsa${i}.txt"
    check "condensed_rsa${i}"         "condensed_rsa.txt"         "correct_condensed_rsa${i}.txt"
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

#!/bin/bash
set -euo pipefail

rm -rf *.log CA Alice Bob
rm -f Signature.txt Verification.txt PK.txt SK.txt

gcc KeyGen.c -lcrypto        -o CA
gcc Sign.c   -lcrypto -lm    -o Alice
gcc Verify.c -lcrypto -lm    -o Bob

declare -A SIGNATURE_ELEMENTS=( [128]=36 [256]=32 [1024]=25 )

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

# run_test <i> <t>
run_test() {
    local i=$1 t=$2 k=${SIGNATURE_ELEMENTS[$2]}

    echo "=== Seed${i}, t=${t}, k=${k} ==="

    ./CA    Seed${i}.txt           ${t}      >> CA_${i}_${t}.log
    ./Alice Message${i}.txt ${t} ${k}  > Alice_${i}_${t}.log
    ./Bob   Message${i}.txt ${t} ${k}  > Bob_${i}_${t}.log

    check "SK_${i}_${t}"        "SK.txt"        "Correct_SK_${i}_${t}.txt"
    check "PK_${i}_${t}"        "PK.txt"        "Correct_PK_${i}_${t}.txt"
    check "Signature_${i}_${t}" "Signature.txt" "Correct_Signature_${i}_${t}.txt"

    echo "  Verification: $(cat Verification.txt)"
    echo ""
}

for t in 128 256 1024; do
    for i in 1 2; do
        run_test "$i" "$t"
    done
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

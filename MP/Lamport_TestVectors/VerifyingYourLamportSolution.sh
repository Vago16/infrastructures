#!/bin/sh

NUM_TESTS=3

CA_SRC="KeyGen.c"
ALICE_SRC="Sign.c"
BOB_SRC="Verify.c"

CA_BIN="CA"
ALICE_BIN="Alice"
BOB_BIN="Bob"

clear() {
  rm -rf *.log CA Alice Bob
  rm -f Signature.txt Verification.txt PK.txt SK.txt
}

compile() {
    gcc $CA_SRC    -lcrypto -o CA
    gcc $ALICE_SRC -lcrypto -o $ALICE_BIN
    gcc $BOB_SRC   -lcrypto -o $BOB_BIN
}

check_file() {
    label="$1"
    got="$2"
    expected="$3"

    if [ ! -f "$got" ]; then
        echo "  MISSING  $label ($got not found)"
        return
    fi
    if [ ! -f "$expected" ]; then
        echo "  SKIP     $label (no reference $expected)"
        return
    fi

    if cmp -s "$got" "$expected"; then
        echo "  PASS     $label"
    else
        echo "  FAIL     $label does not match $expected"
    fi
}

run_tests() {
    passed=0
    failed=0

    for i in $(seq 1 $NUM_TESTS); do
        echo "Test [$i/$NUM_TESTS]"

        ./$CA_BIN    Seed$i.txt     > CA$i.log
        ./$ALICE_BIN Message$i.txt  > Alice$i.log
        ./$BOB_BIN   Message$i.txt  > Bob$i.log

        check_file "SK$i"         "SK.txt"        "CorrectSK$i.txt"
        check_file "PK$i"         "PK.txt"        "CorrectPK$i.txt"
        check_file "Signature$i"  "Signature.txt" "CorrectSignature$i.txt"

        if [ -f "Verification.txt" ]; then
            echo "  Verification: $(cat Verification.txt)"
        fi

        # tally pass/fail from last cmp result (recheck quietly)
        for pair in "SK.txt CorrectSK$i.txt" "PK.txt CorrectPK$i.txt" "Signature.txt CorrectSignature$i.txt"; do
            got=$(echo $pair | cut -d' ' -f1)
            exp=$(echo $pair | cut -d' ' -f2)
            [ -f "$got" ] && [ -f "$exp" ] && {
                cmp -s "$got" "$exp" && passed=$((passed+1)) || failed=$((failed+1))
            }
        done

        echo ""
    done

    echo "Results: $passed passed, $failed failed ($(( passed + failed )) total checks)"
}

clear
compile
run_tests

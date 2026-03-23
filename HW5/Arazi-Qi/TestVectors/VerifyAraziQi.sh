#!/usr/bin/env bash
set -euo pipefail

# Always run from this script's directory (TestVectors)
cd "$(dirname "$0")"

cmp_or_fail() {
  local generated="$1"
  local expected="$2"
  local msg="$3"

  if ! [[ -f "$generated" ]]; then
    echo "ERROR: Generated file '$generated' not found ($msg)." >&2
    exit 1
  fi
  if ! [[ -f "$expected" ]]; then
    echo "ERROR: Expected file '$expected' not found ($msg)." >&2
    exit 1
  fi

  # Normalize contents (strip whitespace/newlines) before comparison
  local gen_norm exp_norm
  gen_norm="$(tr -d ' \t\r\n' < "$generated")"
  exp_norm="$(tr -d ' \t\r\n' < "$expected")"

  if [[ "$gen_norm" != "$exp_norm" ]]; then
    echo "ERROR: Mismatch for $msg (after normalizing whitespace)." >&2
    echo "  Generated ($generated) raw content:" >&2
    cat "$generated" >&2 || true
    echo "  Expected  ($expected) raw content:" >&2
    cat "$expected" >&2 || true
    echo "  Generated (normalized): $gen_norm" >&2
    echo "  Expected  (normalized): $exp_norm" >&2
    exit 1
  fi

  echo "  OK: $msg"
}

gcc -Wall -Wextra -O2 ca.c RequiredFunctions.c -o ca -lcrypto

gcc -Wall -Wextra -O2 alice.c RequiredFunctions.c -o alice -lcrypto

gcc -Wall -Wextra -O2 bob.c RequiredFunctions.c -o bob -lcrypto

for n in 1 2 3; do
  echo "========================================"
  echo "[Test $n] Starting Arazi–Qi verification"

  # Clean artifacts that are regenerated each run
  rm -f \
    alice_private_xa.txt alice_public_Ua.txt \
    bob_private_xb.txt bob_public_Ub.txt \
    ca_master_secret_d.txt ca_master_public_D.txt \
    alice_ephemeral_pa.txt alice_ephemeral_Ea.txt \
    bob_ephemeral_pb.txt bob_ephemeral_Eb.txt \
    alice_shared_key_Kab.txt bob_shared_key_Kab.txt

  echo "[Test $n] Running CA..."
  ./ca "Correct_b_${n}.txt" "Correct_b_a_${n}.txt" "Correct_b_b_${n}.txt"

  echo "[Test $n] Verifying CA outputs..."
  cmp_or_fail "alice_private_xa.txt" "Correct_alice_private_xa_${n}.txt" "alice_private_xa (x_a) for n=${n}"
  cmp_or_fail "alice_public_Ua.txt" "Correct_alice_public_Ua_${n}.txt" "alice_public_Ua (U_a) for n=${n}"
  cmp_or_fail "bob_private_xb.txt" "Correct_bob_private_xb_${n}.txt" "bob_private_xb (x_b) for n=${n}"
  cmp_or_fail "bob_public_Ub.txt" "Correct_bob_public_Ub_${n}.txt" "bob_public_Ub (U_b) for n=${n}"
  cmp_or_fail "ca_master_public_D.txt" "Correct_ca_master_public_D_${n}.txt" "ca_master_public_D (D) for n=${n}"
  cmp_or_fail "ca_master_secret_d.txt" "Correct_ca_master_secret_d_${n}.txt" "ca_master_secret_d (d) for n=${n}"

  echo "[Test $n] Running Alice (ephemeral generation)..."
  ./alice "alice_private_xa.txt" "alice_public_Ua.txt" "Correct_alice_ephemeral_pa_${n}.txt" "bob_public_Ub.txt" "ca_master_public_D.txt"

  echo "[Test $n] Verifying Alice ephemeral output..."
  cmp_or_fail "alice_ephemeral_Ea.txt" "Correct_alice_ephemeral_Ea_${n}.txt" "alice_ephemeral_Ea for n=${n}"

  echo "[Test $n] Running Bob (ephemeral + shared key)..."
  ./bob "bob_private_xb.txt" "bob_public_Ub.txt" "Correct_bob_ephemeral_pb_${n}.txt" "alice_public_Ua.txt" "ca_master_public_D.txt"

  echo "[Test $n] Verifying Bob outputs..."
  cmp_or_fail "bob_ephemeral_Eb.txt" "Correct_bob_ephemeral_Eb_${n}.txt" "bob_ephemeral_Eb for n=${n}"
  cmp_or_fail "bob_shared_key_Kab.txt" "Correct_shared_key_Kab_${n}.txt" "bob_shared_key_Kab for n=${n}"

  echo "[Test $n] Running Alice again (shared key confirmation)..."
  ./alice "alice_private_xa.txt" "alice_public_Ua.txt" "Correct_alice_ephemeral_pa_${n}.txt" "bob_public_Ub.txt" "ca_master_public_D.txt"

  echo "[Test $n] Verifying Alice shared key..."
  cmp_or_fail "alice_shared_key_Kab.txt" "Correct_shared_key_Kab_${n}.txt" "alice_shared_key_Kab for n=${n}"

  echo "[Test $n] SUCCESS: All comparisons passed."
  echo
 done

echo "========================================"
echo "ALL TESTS PASSED: Arazi–Qi implementation matches all provided test vectors."

# Cleanup: remove all non-Correct .txt files generated during testing
echo "Cleaning up generated .txt files (keeping only 'Correct*')..."
find . -maxdepth 1 -type f -name '*.txt' ! -name 'Correct*' -exec rm -f {} +

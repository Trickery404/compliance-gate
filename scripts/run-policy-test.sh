#!/usr/bin/env bash

set +e

BASELINE="/home/student/compliance-evidence/hardened-run/baseline/approved-baseline.json"
INITIAL_RESULTS="/home/student/compliance-evidence/hardened-run/initial-run/scan-results.xml"
DRIFT_RESULTS="/home/student/compliance-evidence/hardened-run/drift-run/scan-results.xml"

OUTPUT_DIR="/home/student/compliance-evidence/hardened-run/policy-tests"
LOG_FILE="$OUTPUT_DIR/policy-test-output.txt"

mkdir -p "$OUTPUT_DIR"

: > "$LOG_FILE"

run_test() {
    TEST_NAME="$1"
    RESULTS="$2"
    POLICY="$3"
    OUTPUT="$4"

    {
        echo "============================================================"
        echo "TEST: $TEST_NAME"
        echo "============================================================"
        echo
        echo "COMMAND:"
        echo "python3 -m compliance_gate evaluate \\"
        echo "  --results \"$RESULTS\" \\"
        echo "  --policy \"$POLICY\" \\"
        echo "  --baseline \"$BASELINE\" \\"
        echo "  --output \"$OUTPUT\""
        echo
        echo "OUTPUT:"
    } >> "$LOG_FILE"

    python3 -m compliance_gate evaluate \
        --results "$RESULTS" \
        --policy "$POLICY" \
        --baseline "$BASELINE" \
        --output "$OUTPUT" \
        >> "$LOG_FILE" 2>&1

    EXIT_CODE=$?

    {
        echo
        echo "EXIT CODE: $EXIT_CODE"
        echo
        echo "DECISION REPORT:"
    } >> "$LOG_FILE"

    if [ -f "$OUTPUT" ]; then
        cat "$OUTPUT" >> "$LOG_FILE"
    else
        echo "Decision report was not generated." >> "$LOG_FILE"
    fi

    echo >> "$LOG_FILE"
}

run_test \
    "P1 - fail_on_new with initial baseline result" \
    "$INITIAL_RESULTS" \
    "policy/tests/fail-on-new.yaml" \
    "$OUTPUT_DIR/fail-on-new-initial.json"

run_test \
    "P2 - fail_on_new with configuration-drift result" \
    "$DRIFT_RESULTS" \
    "policy/tests/fail-on-new.yaml" \
    "$OUTPUT_DIR/fail-on-new-drift.json"

run_test \
    "P3 - fail_all with initial baseline result" \
    "$INITIAL_RESULTS" \
    "policy/tests/fail-all.yaml" \
    "$OUTPUT_DIR/fail-all-initial.json"

run_test \
    "P5 - active exception with configuration-drift result" \
    "$DRIFT_RESULTS" \
    "policy/tests/active-exception.yaml" \
    "$OUTPUT_DIR/active-exception.json"

run_test \
    "P6 - expired exception with configuration-drift result" \
    "$DRIFT_RESULTS" \
    "policy/tests/expired-exception.yaml" \
    "$OUTPUT_DIR/expired-exception.json"

run_test \
    "P7 - invalid policy" \
    "$INITIAL_RESULTS" \
    "policy/tests/invalid-policy.yaml" \
    "$OUTPUT_DIR/invalid-policy.json"

echo "All policy tests completed."
echo "Combined output written to:"
echo "$LOG_FILE"

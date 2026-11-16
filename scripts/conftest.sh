#!/usr/bin/env sh
# Check workflow supply-chain policy; verify runs its Rego unit tests instead.
#
# Usage:
#   scripts/conftest.sh                 check every workflow and local composite action (the default)
#   scripts/conftest.sh verify          run the Rego unit tests, and check that the bad
#                                       workflow fixtures are collected and denied
#   scripts/conftest.sh test --no-color plain output
#
# Requires conftest 0.69.0 on PATH (CI installs the checksum-verified release).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

if ! command -v conftest > /dev/null 2>&1; then
  echo "conftest is not on PATH. Install conftest 0.69.0 before running this script." >&2
  exit 127
fi

POLICY_DIR=.policy-as-code/.conftest/workflows

MODE=test
if [ "${1:-}" = "verify" ]; then
  MODE=verify
  shift
elif [ "${1:-}" = "test" ]; then
  shift
fi

# Every workflow and local composite action under a repo root. GitHub accepts both .yml and
# .yaml workflows, so both are globbed: a .yaml workflow was once never checked. A local
# composite action's steps run with the token of the job that calls it, so every
# action.yml/action.yaml under .github/ is checked too, at any depth. The workflow policy denies
# a local `uses:` outside ./.github/, so no local action can sit outside this scan.
# A pattern that matches nothing stays literal in sh, so each glob candidate is kept only when
# the file exists. The result is space-separated: these paths hold no spaces.
workflow_targets_under() {
  target_root=$1
  targets=""
  for candidate in \
    "$target_root"/.github/workflows/*.yml \
    "$target_root"/.github/workflows/*.yaml; do
    if [ -f "$candidate" ]; then
      targets="$targets $candidate"
    fi
  done
  if [ -d "$target_root/.github" ]; then
    action_files=$(find "$target_root/.github" -type f \( -name action.yml -o -name action.yaml \) | sort)
    for action_file in $action_files; do
      targets="$targets $action_file"
    done
  fi
  echo "$targets"
}

# The bad fixture tree must FAIL the workflow policy. It proves that workflow_targets_under
# collects a .yaml workflow and a composite action, and that the policy then denies them. A
# Rego unit test alone cannot show this: it never runs the target glob.
WORKFLOW_BAD_FIXTURE_ROOT="$POLICY_DIR/fixtures/bad"

check_bad_workflow_fixtures_fail() {
  echo "--- bad workflow fixtures must fail ($WORKFLOW_BAD_FIXTURE_ROOT)"
  fixture_targets=$(workflow_targets_under "$WORKFLOW_BAD_FIXTURE_ROOT")
  fixture_status=0
  for expected_fixture in \
    "$WORKFLOW_BAD_FIXTURE_ROOT/.github/workflows/deploy.yaml" \
    "$WORKFLOW_BAD_FIXTURE_ROOT/.github/actions/setup/action.yaml" \
    "$WORKFLOW_BAD_FIXTURE_ROOT/.github/actions/deploy/gcp/action.yml"; do
    case " $fixture_targets " in
      *" $expected_fixture "*) ;;
      *)
        echo "FAIL: $expected_fixture is not collected as a workflow target." >&2
        fixture_status=1
        ;;
    esac
  done
  # shellcheck disable=SC2086
  if conftest test --no-color --policy "$POLICY_DIR" $fixture_targets > /dev/null; then
    echo "FAIL: the bad workflow fixtures passed the workflow policy; they must be denied." >&2
    return 1
  fi
  if [ "$fixture_status" -ne 0 ]; then
    return 1
  fi
  echo "ok: the bad workflow fixtures are denied"
}

if [ "$MODE" = "verify" ]; then
  conftest verify --policy "$POLICY_DIR" "$@"
  check_bad_workflow_fixtures_fail
  exit 0
fi

# EVERY workflow and local composite action, not one named file: a workflow nobody remembered
# to list here is exactly the one that would carry a tag-pinned action.
# shellcheck disable=SC2086
exec conftest test --policy "$POLICY_DIR" $(workflow_targets_under .) "$@"

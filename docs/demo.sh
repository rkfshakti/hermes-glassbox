#!/usr/bin/env bash
# Glassbox demo script — used for the recorded terminal demo and safe to run locally.
# Set HERMES_CMD if `hermes` is not on PATH (for example:
#   HERMES_CMD="/path/to/hermes-agent/.venv/bin/python -m hermes_cli.main" bash docs/demo.sh
set -euo pipefail
H="${HERMES_CMD:-hermes}"

clear
printf '\033[1mHermes Glassbox\033[0m — a contained, auditable terminal backend\n\n'
sleep 0.8

$H glassbox status
sleep 1.2

$H glassbox verify
sleep 1.2

$H glassbox demo
sleep 1.2

printf '\n\033[2mAudit timeline (last 8 commands)\033[0m\n'
$H glassbox report --limit 8
sleep 1.5

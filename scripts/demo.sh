#!/usr/bin/env bash
# 90-second demo path for the EvidenceGene Court.
# Assumes case001 memory image is unzipped at cases/case001/citadeldc01.mem
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MEM="${1:-cases/case001/citadeldc01.mem}"

echo "== 1. Health =="
uv run egc-court health

echo
echo "== 2. Court investigation (memory: dc01) =="
uv run egc-court investigate --memory "$MEM" --source memory:dc01

echo
echo "== 3. Audit chain verification =="
uv run egc-court verify

echo
echo "Artifacts:  reports/runs/artifacts.sqlite3"
echo "Audit log:  reports/runs/audit_chain.jsonl"
echo "Findings:   reports/runs/findings.jsonl"

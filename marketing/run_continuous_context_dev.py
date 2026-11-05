#!/usr/bin/env python3
import csv
import json
import os
import re
import subprocess
import sys
import time

LEADS_DIR = os.path.expanduser("~/workspace/agentgate/leads")
HELPER_BIN = os.path.expanduser(
    "~/workspace/custom-connectors/custom.context-dev/bin/context_dev.py"
)
OUTPUT_CSV = os.path.join(LEADS_DIR, "agentgate-leads-continuous.csv")
LOG_FILE = os.path.join(LEADS_DIR, "continuous-run.log")

EXCLUSIONS_FILE = os.path.join(LEADS_DIR, "send-log-exclusions.csv")
DROPPED_FILE = os.path.join(LEADS_DIR, "dropped-artifact-emails.csv")

TARGET_QUERIES = [
    'AI agent "runbook" OR "SRE" OR "DevOps" automation tool',
    'AI agent "database" OR "Postgres" OR "SQL" query execution tool',
    'autonomous AI agent "healthcare" OR "clinical" workflow platform',
    'AI customer support agent "eCommerce" OR "Shopify" tool execution',
    'autonomous "code refactoring" OR "codebase migration" AI agent',
    'AI agent "browser automation" OR "scraping" enterprise platform',
]

BAD_PREFIXES = (
    "jobs@",
    "careers@",
    "press@",
    "privacy@",
    "orders@",
    "security@",
    "billing@",
    "legal@",
)


def log(msg: str):
  line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
  print(line, flush=True)
  with open(LOG_FILE, "a") as f:
    f.write(line + "\n")


def load_exclusions():
  excluded = set()
  for path in (EXCLUSIONS_FILE, DROPPED_FILE):
    if os.path.exists(path):
      with open(path, "r", errors="ignore") as f:
        for line in f:
          parts = [p.strip().lower() for p in line.split(",") if "@" in p]
          excluded.update(parts)
  return excluded


def run_context_dev(action, *args):
  cmd = [sys.executable, HELPER_BIN, action] + list(args)
  res = subprocess.run(cmd, capture_output=True, text=True)
  if res.returncode != 0:
    if "429" in res.stderr or "rate limit" in res.stderr.lower():
      log("Rate limit encountered. Sleeping 30s...")
      time.sleep(30)
      return run_context_dev(action, *args)
    log(f"Error running context_dev: {res.stderr}")
    return None
  try:
    return json.loads(res.stdout)
  except json.JSONDecodeError:
    return None


def main():
  log("Starting continuous Context.dev lead discovery run...")
  exclusions = load_exclusions()
  log(f"Loaded {len(exclusions)} existing excluded email targets.")

  file_exists = os.path.exists(OUTPUT_CSV)
  out_f = open(OUTPUT_CSV, "a", newline="", encoding="utf-8")
  writer = csv.writer(out_f)
  if not file_exists:
    writer.writerow([
        "company",
        "domain",
        "contact_email",
        "source_query",
        "offer_tier",
        "hook_summary",
    ])
    out_f.flush()

  for query in TARGET_QUERIES:
    log(f"Executing query angle: {query}")
    data = run_context_dev("company-search", query)
    if not data or "companies" not in data:
      time.sleep(2)
      continue

    for comp in data.get("companies", []):
      domain = comp.get("domain", "").lower()
      email = comp.get("email", "").lower()
      name = comp.get("name", "")
      desc = comp.get("description", "")

      if not email or not domain or "@" not in email:
        continue
      if email in exclusions or any(email.startswith(p) for p in BAD_PREFIXES):
        continue
      if email.endswith(".pec.it"):
        continue

      writer.writerow([name, domain, email, query, "$450", desc[:200]])
      out_f.flush()
      exclusions.add(email)
      log(f"Verified & saved lead: {name} ({email})")

      # Strictly serial pacing to avoid 429 backoff
      time.sleep(2)

  out_f.close()
  log("Discovery cycle completed. Inspecting remaining usage...")
  usage = run_context_dev("get-usage")
  if usage:
    log(f"Remaining usage status: {usage}")


if __name__ == "__main__":
  main()

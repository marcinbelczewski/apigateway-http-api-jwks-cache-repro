"""Offline follow-up counts and latency ranges. Association rules are in README.md."""

import argparse
import json
from pathlib import Path

from repro import coverage, join_access, normalize_events


def api_interval(event):
    if not event:
        return None
    try:
        duration = int(event["responseLatency"])
        # Only old logs lacking the explicit field use the approximate timestamp.
        source = "requestTimeEpoch" if "requestTimeEpoch" in event else "log_timestamp_ms"
        start = int(event[source])
        if start >= 0 and duration >= 0:
            return {"start_ms": start, "end_ms": start + duration, "source": source}
    except (KeyError, TypeError, ValueError):
        pass
    return None


def summarize(clients, access, issuer):
    rows = join_access(clients, normalize_events(access))
    key_starts = [e["started_ms"] for e in normalize_events(issuer)
                  if e.get("path") == "/keys" and isinstance(e.get("started_ms"), (int, float))]
    groups = {name: [] for name in ("with_associated_jwks", "without_associated_jwks", "unknown")}
    sources = {"requestTimeEpoch": 0, "log_timestamp_ms": 0}
    for row in rows:
        if row["index"] == 0 or row.get("status") != 200 or "error" in row:
            continue
        interval = api_interval(row["access_log"])
        if interval:
            sources[interval["source"]] += 1
        group = "unknown"
        if interval is not None and row["frontend_ms"] is not None:
            # Inclusive start, exclusive end; handler completion is not constrained.
            fetched = any(interval["start_ms"] <= t < interval["end_ms"] for t in key_starts)
            group = "with_associated_jwks" if fetched else "without_associated_jwks"
        groups[group].append(row["frontend_ms"])
    populations = {}
    for name, values in groups.items():
        known = [value for value in values if value is not None]
        populations[name] = {
            "count": len(values),
            "frontend_ms_range": [min(known), max(known)] if known else None,
        }
    return {
        "coverage": coverage(rows),
        "followup_attempts": sum(row["index"] > 0 for row in rows),
        "successful_followups": populations,
        "api_time_sources": sources,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--wide", action="store_true", help="Read historical *-wide.json exports")
    args = parser.parse_args()
    suffix = "-wide" if args.wide else ""
    clients = [json.loads(line) for line in (args.directory / "client.jsonl").read_text().splitlines()]
    access, issuer = [json.loads((args.directory / f"{name}{suffix}.json").read_text())
                      for name in ("api-access", "issuer-requests")]
    report = summarize(clients, access, issuer)
    print(json.dumps({"run": str(args.directory), "wide": args.wide, **report}, indent=2))
    raise SystemExit(int(not report["coverage"]["complete"]))

"""One seed, 240 seconds quiet, then 30 sequential requests capped at 1 RPS."""

import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import boto3
import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parent
KEY = ROOT / ".local/signing-key.pem"
JWKS = ROOT / ".local/jwks.json"
LOG_PADDING_MS = 60_000


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def public_jwk(key):
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    thumbprint = json.dumps(
        {k: jwk[k] for k in ("e", "kty", "n")}, separators=(",", ":"), sort_keys=True
    )
    return {
        **jwk,
        "kid": hashlib.sha256(thumbprint.encode()).hexdigest(),
        "use": "sig",
        "alg": "RS256",
    }


def prepare():
    KEY.parent.mkdir(mode=0o700, exist_ok=True)
    if not KEY.exists():
        if JWKS.exists():
            raise RuntimeError("Missing private key; refusing to replace existing JWKS.")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(KEY, "xb", opener=lambda p, f: os.open(p, f, 0o600)) as file:
            file.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
    key = serialization.load_pem_private_key(KEY.read_bytes(), password=None)
    public = {"keys": [public_jwk(key)]}
    if JWKS.exists() and json.loads(JWKS.read_text()) != public:
        raise RuntimeError("Private key and JWKS differ; refusing to rotate keys.")
    if not JWKS.exists():
        save(JWKS, public)
    print("Local key retained; Terraform reads only .local/jwks.json.")


def mint(config):
    if hashlib.sha256(JWKS.read_bytes()).hexdigest() != config["jwks_sha256"]:
        raise RuntimeError("Local JWKS differs from Terraform output.")
    key = serialization.load_pem_private_key(KEY.read_bytes(), password=None)
    jwk = json.loads(JWKS.read_text())["keys"][0]
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": config["issuer"],
            "aud": config["audience"],
            "sub": "repro",
            "iat": now - 5,
            "exp": now + 3600,
        },
        key,
        algorithm="RS256",
        headers={"kid": jwk["kid"]},
    )
    jwt.decode(
        token,
        jwt.PyJWK.from_dict(jwk).key,
        algorithms=["RS256"],
        audience=config["audience"],
        issuer=config["issuer"],
    )
    return token


def frontend(event):
    # Missing integration timing is unknown, not zero. This is not a JWT timer.
    try:
        response, integration = int(event["responseLatency"]), int(event["integrationLatency"])
        if str(event["status"]) == "200" and 0 <= integration <= response:
            return response - integration
    except (KeyError, TypeError, ValueError):
        pass
    return None


def normalize_events(entries):
    """Accept both runner JSON and raw CloudWatch FilterLogEvents exports."""
    events = []
    for entry in entries:
        if "message" in entry:
            try:
                event = json.loads(entry["message"])
            except (ValueError, TypeError):
                continue  # Lambda START/END/REPORT lines are not application JSON.
            if isinstance(event, dict):
                events.append({**event, "log_timestamp_ms": entry["timestamp"]})
        elif isinstance(entry, dict):
            events.append(entry)
    return events


def api_interval(event):
    """Legacy event timestamps are an explicitly labelled start-time approximation."""
    if not event:
        return None
    try:
        duration = int(event["responseLatency"])
        source = "requestTimeEpoch"
        if source not in event:  # Historical logs predate explicit request-start logging.
            source = "log_timestamp_ms"
        start = int(event[source])
        if start >= 0 and duration >= 0:
            return {"start_ms": start, "end_ms": start + duration, "source": source}
    except (KeyError, TypeError, ValueError):
        pass
    return None


def correlate(rows, access, issuer):
    by_id = {event["requestId"]: event for event in access if event.get("requestId")}
    correlated = []
    for original in rows:
        row = dict(original)
        row["access_log"] = by_id.get(row.get("request_id"))
        row["frontend_ms"] = frontend(row["access_log"])
        interval = api_interval(row["access_log"])
        row["api_interval"] = interval
        # Fetch START must fall in [API start, API start + responseLatency).
        # Completion need not be contained; no clock tolerance is silently applied.
        row["issuer_events_starting_in_api_interval"] = None if interval is None else [
            event for event in issuer
            if isinstance(event.get("started_ms"), (int, float))
            and interval["start_ms"] <= event["started_ms"] < interval["end_ms"]
        ]
        correlated.append(row)
    return correlated


def coverage(rows):
    responses = [row for row in rows if row.get("status") is not None]
    expected = [row for row in rows if row.get("request_id")]
    matched = sum(row["access_log"] is not None for row in expected)
    missing_ids = sum(not row.get("request_id") for row in responses)
    return {
        "attempts": len(rows),
        "http_responses": len(responses),
        "attempts_without_http_response": len(rows) - len(responses),
        "request_ids": len(expected),
        "matched_request_ids": matched,
        "responses_without_request_id": missing_ids,
        "complete": bool(expected) and matched == len(expected) and missing_ids == 0,
    }


def analyze(directory, wide=False):
    """Analyze saved evidence only; print JSON without modifying the run directory."""
    suffix = "-wide" if wide else ""
    paths = {
        name: directory / f"{name}{suffix}.json"
        for name in ("api-access", "issuer-requests")
    }
    streams = {
        name: normalize_events(json.loads(path.read_text())) for name, path in paths.items()
    }
    clients = [json.loads(line) for line in (directory / "client.jsonl").read_text().splitlines()]
    rows = correlate(clients, streams["api-access"], streams["issuer-requests"])
    populations = {
        name: [] for name in ("with_associated_jwks", "without_associated_jwks", "unknown")
    }
    for row in rows:
        if row["index"] == 0 or row.get("status") != 200 or "error" in row:
            continue
        events = row["issuer_events_starting_in_api_interval"]
        if events is None or row["frontend_ms"] is None:
            population = "unknown"
        else:
            has_keys = any(event.get("path") == "/keys" for event in events)
            population = "with_associated_jwks" if has_keys else "without_associated_jwks"
        populations[population].append(row)
    summary = {}
    for name, population in populations.items():
        timings = [row["frontend_ms"] for row in population if row["frontend_ms"] is not None]
        summary[name] = {
            "count": len(population),
            "frontend_ms_range": [min(timings), max(timings)] if timings else None,
        }
    report = {
        "run": directory.name,
        "inputs": {name: str(path) for name, path in paths.items()},
        "coverage": coverage(rows),
        "association_rule": (
            "Issuer start in [API start, API start + responseLatency); "
            "no tolerance; completion may fall outside."
        ),
        "legacy_clock_caveat": (
            "Missing requestTimeEpoch falls back to CloudWatch event timestamp, "
            "an approximate API start. No cross-service request-ID linkage."
        ),
        "issuer_coverage_caveat": (
            "No associated fetch means none observed, not proof of a cache hit. "
            "Padded logs may contain unrelated traffic or deployment prefetch."
        ),
        "successful_followups": summary,
        "rows": rows,
    }
    print(json.dumps(report, indent=2))
    return report["coverage"]["complete"]


def collect(directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    config = manifest["deployment"]
    logs = boto3.client("logs", region_name=config["region"])
    streams = {}
    window = {
        "started_ms": max(0, manifest["started_ms"] - LOG_PADDING_MS),
        "ended_ms": manifest["ended_ms"] + LOG_PADDING_MS,
        "padding_ms": LOG_PADDING_MS,
    }
    save(directory / "collection-window.json", window)
    for name, group in (
        ("api-access", "access_log_group"),
        ("issuer-requests", "issuer_log_group"),
    ):
        events = []
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=config[group],
            startTime=window["started_ms"],
            endTime=window["ended_ms"],
        ):
            events.extend(normalize_events(page.get("events", [])))
        save(directory / f"{name}.json", events)
        streams[name] = events
    clients = [json.loads(line) for line in (directory / "client.jsonl").read_text().splitlines()]
    rows = correlate(clients, streams["api-access"], streams["issuer-requests"])
    save(directory / "correlated.json", rows)
    log_coverage = coverage(rows)
    followups = [row for row in rows if row["index"] > 0]
    slow = sum(row["frontend_ms"] is not None and row["frontend_ms"] >= 400 for row in followups)
    print(
        f"API logs: {log_coverage['matched_request_ids']}/{log_coverage['request_ids']} request IDs matched; "
        f"follow-ups >=400ms: {slow}/{len(followups)}"
    )
    print(
        f"Attempts without HTTP response: {log_coverage['attempts_without_http_response']}; "
        f"HTTP responses without request ID: {log_coverage['responses_without_request_id']}"
    )
    print(
        f"Issuer requests: {len(streams['issuer-requests'])}; compare timestamps, not just counts."
    )
    return log_coverage["complete"]


def run():
    config = json.loads(
        subprocess.check_output(
            ["terraform", f"-chdir={ROOT / 'infra'}", "output", "-json", "repro"], text=True
        )
    )
    token = mint(config)  # Offline: neither endpoint is warmed by token creation.
    directory = ROOT / "results" / str(time.time_ns())
    directory.mkdir(parents=True)
    manifest = {
        "deployment": config,
        "started_ms": int(time.time() * 1000),
        "scenario": "1 seed; 240s quiet; 30 sequential requests capped at 1 RPS",
    }
    save(directory / "manifest.json", manifest)
    print(f"Evidence: {directory}", flush=True)
    successful = True
    try:
        with (
            (directory / "client.jsonl").open("x") as file,
            httpx.Client(
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
                follow_redirects=False,
            ) as client,
        ):
            for index in range(31):
                if index == 1:
                    print("Quiet for 240 seconds...", flush=True)
                    time.sleep(240)
                row = {"index": index, "started_ms": int(time.time() * 1000), "status": None}
                started = time.monotonic()
                try:
                    response = client.get(config["probe_url"])
                    row.update(
                        status=response.status_code,
                        request_id=response.headers.get("apigw-requestid"),
                    )
                    if response.status_code == 200:
                        row["backend"] = response.json()
                except (httpx.HTTPError, ValueError) as error:
                    row["error"] = type(error).__name__  # No token or raw request details.
                elapsed = time.monotonic() - started
                row["client_ms"] = round(elapsed * 1000, 3)
                file.write(json.dumps(row) + "\n")
                file.flush()
                print(json.dumps(row), flush=True)
                ok = row["status"] == 200 and "error" not in row and bool(row.get("request_id"))
                successful &= ok
                if index == 0 and not ok:
                    break  # Do not follow up a failed seed.
                if 0 < index < 30:
                    time.sleep(max(0, 1 - elapsed))  # No concurrency or catch-up bursts.
    finally:
        manifest["ended_ms"] = int(time.time() * 1000) + 1
        save(directory / "manifest.json", manifest)
    print("Waiting 90 seconds for logs...", flush=True)
    time.sleep(90)
    complete = collect(directory)
    return 0 if successful and complete else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "run", "collect", "analyze"])
    parser.add_argument(
        "directory", nargs="?", type=Path, help="Existing run directory for collect/analyze"
    )
    parser.add_argument("--wide", action="store_true", help="Analyze historical *-wide.json exports")
    args = parser.parse_args()
    if args.command in ("collect", "analyze") and args.directory is None:
        parser.error(f"{args.command} requires a run directory")
    if args.wide and args.command != "analyze":
        parser.error("--wide is only valid with analyze")
    if args.command == "prepare":
        prepare()
    elif args.command == "analyze":
        raise SystemExit(int(not analyze(args.directory, wide=args.wide)))
    else:
        raise SystemExit(run() if args.command == "run" else int(not collect(args.directory)))

"""One seed, 240 seconds without runner requests, then 30 requests capped at 1 RPS."""

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


def join_access(clients, access):
    by_id = {event["requestId"]: event for event in access if event.get("requestId")}
    rows = []
    for client in clients:
        event = by_id.get(client.get("request_id"))
        rows.append({**client, "access_log": event, "frontend_ms": frontend(event)})
    return rows


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
    rows = join_access(clients, streams["api-access"])
    save(directory / "correlated.json", rows)
    log_coverage = coverage(rows)
    print(json.dumps({"api_log_coverage": log_coverage}))
    return log_coverage["complete"]


def run():
    config = json.loads(
        subprocess.check_output(
            ["terraform", f"-chdir={ROOT / 'infra'}", "output", "-json", "repro"], text=True
        )
    )
    token = mint(config)  # Local signing and verification; no endpoint requests.
    directory = ROOT / "results" / str(time.time_ns())
    directory.mkdir(parents=True)
    manifest = {
        "deployment": config,
        "started_ms": int(time.time() * 1000),
        "scenario": "1 seed; 240s without runner requests; 30 sequential requests capped at 1 RPS",
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
                    print("Waiting 240 seconds without sending requests...", flush=True)
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
    parser.add_argument("command", choices=["prepare", "run", "collect"])
    parser.add_argument("directory", nargs="?", type=Path, help="Existing run directory for collect")
    args = parser.parse_args()
    if args.command == "collect" and args.directory is None:
        parser.error("collect requires a run directory")
    if args.command == "prepare":
        prepare()
    else:
        raise SystemExit(run() if args.command == "run" else int(not collect(args.directory)))

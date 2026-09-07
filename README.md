# HTTP API JWT / JWKS retrieval reproduction

Does API Gateway repeatedly retrieve signing keys while validating an unchanged
JWT at low request rates? This experiment records retrievals and API latency
without an external identity provider.

```text
local runner -> HTTP API native JWT authorizer -> no-op Lambda
                         |
                         +-> public discovery/JWKS Lambda URL (logs each request)
```

The issuer serves fixed metadata and one RSA public key, not a complete OIDC
service. Both responses advertise `Cache-Control: public, max-age=7200`.
**Each `/keys` handler deliberately waits 600 ms**; discovery has no added delay.
This is an experimental delay, not measured Okta latency or throttling. There is
no application rate limiter, but AWS platform limits still apply.

## Run

Requires `uv`, Terraform 1.7+, and sandbox credentials permitted to create HTTP
APIs, Lambdas/Function URLs, IAM roles/policies, and log groups. Collection requires
`logs:FilterLogEvents` on the experiment's API and issuer log groups.

From the repository root:

```bash
uv sync --locked
uv run python -m repro prepare
terraform -chdir=infra init
terraform -chdir=infra plan
terraform -chdir=infra apply
uv run python -m repro run
```

Default Region: `eu-west-1`. Optional `region` and `name` overrides go in ignored
`infra/terraform.tfvars`. `prepare` retains `.local/signing-key.pem` locally (0600);
Terraform reads only the public `.local/jwks.json`. The runner signs and verifies
one token locally, uses it for every request in the run, and never prints or saves it.

One run takes about six minutes and attempts at most 31 API requests:

1. Send one request, called the **seed**. Stop if it fails.
2. Send no further requests for 240 seconds.
3. Send 30 sequential requests, starting at least one second apart. No retries.
4. Wait 90 seconds, then collect logs.

The runner sends no endpoint requests before the seed. API Gateway can fetch
metadata during deployment; historical logs include these requests. A successful
seed establishes that request was authorized, not that every validator retained
the key. The idle interval does not establish cache expiry.

For a zero-delay control, set `JWKS_DELAY_MS = 0` in `lambdas/issuer.py`, apply the
issuer code change with Terraform, and run again. Keep the API, authorizer, issuer
URL, and signing key unchanged. Redeployment is not a controlled cache reset.
No load test or two-hour wait is required by this scenario.

## Evidence and interpretation

The runner writes `results/<run>/`:

- `manifest.json`, `client.jsonl`: deployment, observation window, and every attempt's
  status, latency, API request ID, and backend process diagnostics.
- `collection-window.json`: query bounds, padded by 60 seconds on each side of the
  client window to accommodate clock differences.
- `api-access.json`, `issuer-requests.json`: available logs in those bounds.
- `correlated.json`: client attempts joined to API logs by request ID, with
  `frontend_ms = responseLatency - integrationLatency`.

A constant backend `boot_id` and increasing `request_count` identify reuse of the
same Lambda process. **Frontend time is not a direct authorizer timer.** Missing
or invalid latency remains unknown, not zero.

Recollect late logs without API traffic, or summarize saved files offline:

```bash
uv run python -m repro collect results/<run>
uv run python -m analyze results/<run>
```

`collect` replaces saved log/join files. Coverage requires at least one returned
API ID, a log for every returned ID, and no HTTP response lacking an ID. Attempts
without an HTTP response are reported separately. `run` fails on request failures
or incomplete coverage; `collect` and `analyze` exit based on coverage alone.
Complete API logs do not guarantee complete issuer logs. Padded queries can also
include deployment requests or unrelated traffic.

`analyze` prints coverage, follow-up counts, latency ranges, and timestamp source
counts without modifying evidence. Successful follow-ups are grouped by whether
a logged `/keys` request **starts** in `[API start, API start + responseLatency)`:
start included, end excluded, no tolerance or constraint on handler completion.
API start uses `$context.requestTimeEpoch`. Older logs without it use the CloudWatch
event timestamp as an **approximation**, counted under `log_timestamp_ms` in the
summary. Missing timing goes into `unknown`. No associated fetch means none was
observed, not that a cache hit is proven. There is no cross-service request-ID
link; AWS traces are needed to establish causality and cache scope.

## Saved results: 2026-09-07

Four runs in `eu-west-1` use API `4ayx4w0gte` with the same authorizer, issuer URL,
and signing key. Each run uses one unchanged JWT. Only issuer code changes between
the zero-delay and 600-ms trials; the API and authorizer are not recreated.

Follow-ups only. The last two columns show **request count; frontend range (ms)**,
using the association rule above:

| Trial | 200 / attempts | With fetch | Without fetch |
| --- | ---: | ---: | ---: |
| Baseline 1, 0 ms | 30/30 | 24; 30–101 | 6; 3–4 |
| Baseline 2, 0 ms | 30/30 | 21; 32–81 | 9; 1–5 |
| Delayed 1, 600 ms | 29/30 | 24; 633–695 | 5; 3–5 |
| Delayed 2, 600 ms | 30/30 | 21; 632–670 | 9; 3–5 |

Delayed 1 includes one `ConnectError` without an HTTP response, excluded from latency
groups but retained as an attempt. Delayed 2 has no request errors. The delayed
follow-ups reuse one backend process, with 10–33 ms integration latency (the first
delayed seed is 381 ms). All 94 logged issuer requests across those trials, including
seeds, return 200. Saved issuer Lambda metrics show zero errors and throttles;
each logged `/keys` handler takes 600–601 ms.

Two adjacent requests in delayed 2, **15:57:45–15:58:15 UTC**:

| API request ID | Response ms | Integration ms | Frontend ms |
| --- | ---: | ---: | ---: |
| `DVfHQi__joEEPwQ=` | 16 | 12 | 4 |
| `DVfHagQXDoEEPNw=` | 664 | 24 | 640 |

The latter's approximate interval contains a `/keys` handler at
**15:57:47.817–15:57:48.417 UTC**, returning 200 after the injected 600 ms. No issuer
request is observed in the former's interval. All historical runs use approximate
API start times. In delayed 1, the handler associated with `DVeMpjlCjoEEPJQ=` starts
inside but finishes 28 ms beyond its interval: included by the start-based rule,
not by strict completion containment.

**Repeated retrievals occur without Okta or observed issuer throttling.** Associated
frontend times increase with the injected delay; the other requests remain at a
few milliseconds. This does not explain the original Okta latency or prove a cache
defect. [AWS documents](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html)
that keys *can* be cached for two hours, not a guaranteed single shared cache
populated by one successful validation.

Recalculate from local historical exports without AWS calls:

```bash
for run in 1788794585336770000 1788795026008704000 1788796033007811000 1788796424241067000; do
  uv run python -m analyze "results/$run" --wide
done
```

`--wide` reads `api-access-wide.json` and `issuer-requests-wide.json`, accepting raw
CloudWatch or normalized JSON. Those queries use ±60-second padding; the original
exact client-clock bounds omit the last API record in both baseline runs. The
current collector pads automatically. Existing exports remain unchanged.

Results are Git-ignored. For AWS Support, attach the locally saved
`results/aws-support-request-ids-20260907.txt`: 154 API IDs from these runs and the
earlier Okta probe, plus 190 issuer Lambda IDs in a separate section. It labels
timestamp sources and injected delay. These are different ID namespaces; the
repository link alone does not include the evidence.

## Checks and cleanup

Offline tests cover keys/tokens, metadata responses, latency, log formats,
timestamp selection, interval boundaries, and coverage:

```bash
uv run python -m unittest discover -s tests -v
terraform -chdir=infra validate
```

The public endpoints are billable. API Gateway's 10-RPS throttle is not a cost cap
and does not limit direct issuer requests. Export evidence before cleanup, which
also deletes the log groups:

```bash
terraform -chdir=infra destroy
```

Retain state until destruction completes. Private keys, state, plans, variables,
ZIPs, and results are Git-ignored. Keep private keys local; review staged files and
attachments before sharing. Evidence includes deployed identifiers, not tokens.

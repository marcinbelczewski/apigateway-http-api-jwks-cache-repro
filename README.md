# HTTP API JWT / JWKS cache reproduction

Does API Gateway repeatedly fetch signing keys after successfully validating the
same token? This experiment records API latency and the actual discovery/JWKS
requests, without an external identity provider.

```text
local runner -> HTTP API native JWT authorizer -> no-op Lambda
                         |
                         +-> public discovery/JWKS Lambda URL (logs each request)
```

No Okta, Cognito, CloudFront, or Lambda authorizer. The public issuer is only a
metadata fixture, not a complete OIDC provider. Its application never throttles
requests, although AWS platform limits still apply.

**Each `/keys` request deliberately waits 600 ms** to make repeated retrievals
visible in API latency. Discovery has no artificial delay. Issuer logs record
`artificial_delay_ms`; this is simulated network latency, not a measured Okta delay
or throttling. Set `JWKS_DELAY_MS = 0` in `lambdas/issuer.py` and redeploy for a
zero-delay baseline. Redeployment does not flush API Gateway's key cache.

## Deploy and run

Requires `uv`, Terraform 1.7+, and AWS sandbox credentials with permission to create
HTTP APIs, Lambdas/Function URLs, IAM roles/policies, and log groups. Evidence
collection needs `logs:FilterLogEvents` on the experiment's log groups.

From the repository root:

```bash
uv sync --locked
uv run python -m repro prepare
terraform -chdir=infra init
terraform -chdir=infra plan
terraform -chdir=infra apply
uv run python -m repro run
```

Default Region: `eu-west-1`. Optional `region` and `name` overrides belong in the
ignored `infra/terraform.tfvars`.

`prepare` retains a local RSA private key in `.local/signing-key.pem` (0600).
Terraform reads only the public `.local/jwks.json`. The runner signs and verifies
one token locally and never prints or saves it. Every request uses that same token.

The fixed scenario takes about six minutes:

1. One successful seed request, with no preceding endpoint warm-up.
2. **240 seconds quiet.**
3. **30 sequential requests capped at 1 RPS**, with no retries or catch-up bursts.
4. Wait 90 seconds, then collect logs.

A failed seed stops the follow-up phase. Requests are saved incrementally, including
errors. The command exits nonzero for request failures or incomplete API-log
coverage, not merely for slow successful requests.

## Read the evidence

The runner prints its `results/<run>/` directory:

- `manifest.json`: deployment details, scenario, observation window.
- `client.jsonl`: timestamps, status, latency, API request IDs and Lambda reuse.
- `collection-window.json`: actual log-query bounds, padded by 60 seconds on each
  side of the manifest's client observation window to accommodate clock skew.
- `api-access.json` and `issuer-requests.json`: available logs in that padded window.
- `correlated.json`: client rows joined to access logs by request ID, including
  `frontend_ms = responseLatency - integrationLatency`, the API interval and its
  timestamp source, and issuer requests starting in that interval.

Look for interleaved large/small frontend times with stable integration latency,
then compare their timestamps with discovery and `/keys` requests. The backend's
`boot_id` and increasing `request_count` distinguish process reuse from cold starts.

**Frontend time is not a direct authorizer timer or proof of a cache miss.** Missing
timing stays unknown. Issuer fetches correlate by time, not by protected API request
ID; AWS internal traces are needed to establish worker/cache scope and causality.

Logs can arrive late. Recollect with padded bounds without sending more traffic:

```bash
uv run python -m repro collect results/<run>
```

`collect` reports coverage of returned request IDs separately from attempts with
no HTTP response. A transport error does not count as a missing API log. An HTTP
response without a request ID does make coverage incomplete. `collect` succeeds
when at least one ID is returned, all returned IDs are covered, and none of the
HTTP responses lacks an ID; `run` still exits nonzero for any request failure. Padding is a clock-skew
allowance, not a guarantee of complete logs.

Analyze the saved files offline, without AWS calls or changes to the evidence:

```bash
uv run python -m repro analyze results/<run>
```

The command prints JSON with coverage, follow-up populations, latency ranges, and
per-request associations. It exits nonzero for incomplete API-log coverage, not
for previously recorded request failures, which remain in its output. Redirect
stdout to a new file if a saved report is needed.

**Association rule:** an issuer request's `started_ms` must fall in the half-open
interval `[API start, API start + responseLatency)`. Completion need not fall
inside, and no timing tolerance is applied. The configured access log includes
`$context.requestTimeEpoch` as the explicit API start after deployment. Historical
logs without that field use the CloudWatch event timestamp as an **approximate**
start; each row labels this fallback. Missing or invalid interval timing remains
unknown, not a no-fetch observation. Absence of an associated fetch means none is
observed, not that a cache hit is proven.

Even complete API logs do not guarantee complete issuer logs. The padded window
can include unrelated traffic or deployment prefetch, so total issuer counts are
not follow-up fetch counts. Inspect the issuer log group separately for prefetch
outside the padded window. Another run can be warm: a seed or a two-hour wait does
not prove global cache readiness or a cache flush. This fixture might not reproduce an
external-provider issue. Preserve fast runs as evidence too.

## Measured results (2026-09-07)

Four runs in `eu-west-1` use the same API (`4ayx4w0gte`), authorizer, issuer URL,
and signing key. Each run uses one unchanged valid JWT and the fixed scenario
above. Only the issuer code changes between the zero-delay and 600-ms trials;
the API and authorizer are not recreated or explicitly flushed.

Follow-ups only, excluding seed requests:

| Run | HTTP 200 / attempts | Associated discovery + JWKS pairs | Frontend with / without temporally associated fetch |
| --- | ---: | ---: | --- |
| Baseline 1, no delay | 30/30 | 24 | 30–101 / 3–4 ms |
| Baseline 2, no delay | 30/30 | 21 | 32–81 / 1–5 ms |
| Delayed 1, 600 ms | 29/30 | 24 | 633–695 / 3–5 ms |
| Delayed 2, 600 ms | 30/30 | 21 | 632–670 / 3–5 ms |

The first delayed trial includes one client `ConnectError` with no HTTP response;
it remains in the evidence, not in the latency populations. The second has no
request errors. Both delayed trials reuse one backend Lambda environment, with
10–33 ms integration latency **for follow-ups only**. The first delayed seed has
381 ms integration latency. All **94 issuer requests** across those trials,
including seeds, return HTTP 200; issuer Lambda metrics show **zero errors and
zero throttles**. Each logged `/keys` handler takes 600–601 ms.

The second delayed trial runs at **15:57:45–15:58:15 UTC**. Two adjacent requests:

| API request ID | Response | Integration | Frontend |
| --- | ---: | ---: | ---: |
| `DVfHQi__joEEPwQ=` | 16 ms | 12 ms | 4 ms |
| `DVfHagQXDoEEPNw=` | 664 ms | 24 ms | 640 ms |

The latter's approximate API-side interval contains a `/keys` request at
**15:57:47.817–15:57:48.417 UTC**, returning 200 with `artificial_delay_ms = 600`.
The former has no issuer request in its interval. These are timestamp associations,
not a propagated cross-service request ID. All four historical runs use the
CloudWatch-timestamp fallback described above. In delayed run 1, the `/keys`
request associated with `DVeMpjlCjoEEPJQ=` starts inside its approximate interval
but finishes 28 ms after it ends. The start-based rule includes it; strict
completion containment would not. This discrepancy reinforces that these clocks
and inferred intervals cannot establish exact cross-service causality.

**Repeated retrievals occur without Okta or observed throttling.** Adding 600 ms
makes their cost visible on later successful validations, while the fast path
remains a few milliseconds. The delay is intentional; it does not prove the cause
of Okta's original latency or establish API Gateway's internal cache scope.

Delayed evidence is saved locally in `results/1788796033007811000/` and
`results/1788796424241067000/`, including `correlated-wide.json` and
`analysis-summary.json`. These Git-ignored artifacts are not published here.
For these results, additional read-only log queries widen the original window by
60 seconds on each side, recovering all 61 HTTP-response request IDs. The original
collector uses exact client-clock bounds and clips the final API record in both
baseline runs. The current collector applies this padding automatically, including
when recollecting an old manifest; previously saved artifacts remain unchanged.

Reproduce the table from the saved historical widened exports, without querying
AWS or overwriting the original analysis:

```bash
for run in 1788794585336770000 1788795026008704000 1788796033007811000 1788796424241067000; do
  uv run python -m repro analyze "results/$run" --wide
done
```

`--wide` explicitly selects `api-access-wide.json` and `issuer-requests-wide.json`;
there is no automatic fallback between old and new evidence files. Both raw
CloudWatch exports and the runner's normalized JSON format are supported.

For AWS Support, attach `results/aws-support-request-ids-20260907.txt` as well as
linking the repository. This local export includes all 154 API request IDs from
the four standalone runs and the earlier Okta-backed probe, plus 190 issuer Lambda
request IDs in a separate section. It labels timestamp sources and the artificial
delay. API and issuer IDs are different namespaces. The repository link alone does
not provide these Git-ignored results; review attachments before sharing.

## Local checks and cleanup

Three offline checks cover token/key consistency, discovery/JWKS responses, and
frontend-time calculation:

```bash
uv run python -m unittest discover -s tests -v
terraform -chdir=infra validate
```

The public endpoints are billable. API Gateway has a 10-RPS stage throttle, which
is not a cost cap. Use an isolated sandbox and destroy it when finished:

```bash
terraform -chdir=infra destroy
```

Export evidence first: destruction also deletes the log groups. Keep Terraform
state until cleanup completes. Keys, state, plans, variable files, generated ZIPs,
and results are Git-ignored. Review exact staged files before publishing; evidence
contains deployed identifiers even though it excludes tokens. Keep private keys
local, including when choosing a Terraform execution environment.

Reference: [AWS JWT authorizer documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html)
says API Gateway **can** cache public keys for two hours; it does not define a
single shared cache or guarantee that one seed warms all validators.

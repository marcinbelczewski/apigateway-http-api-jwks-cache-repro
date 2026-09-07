# HTTP API JWT / JWKS cache reproduction

Does API Gateway repeatedly fetch signing keys after successfully validating the
same token? This experiment records API latency and the actual discovery/JWKS
requests, without an external identity provider.

```text
local runner -> HTTP API native JWT authorizer -> no-op Lambda
                         |
                         +-> public discovery/JWKS Lambda URL (logs each request)
```

No Okta, Cognito, CloudFront, Lambda authorizer, or artificial latency. The public
issuer is only a metadata fixture, not a complete OIDC provider. Its application
never throttles requests, although AWS platform limits still apply.

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
- `api-access.json` and `issuer-requests.json`: available logs in that window.
- `correlated.json`: client rows joined to access logs by request ID, including
  `frontend_ms = responseLatency - integrationLatency`.

Look for interleaved large/small frontend times with stable integration latency,
then compare their timestamps with discovery and `/keys` requests. The backend's
`boot_id` and increasing `request_count` distinguish process reuse from cold starts.

**Frontend time is not a direct authorizer timer or proof of a cache miss.** Missing
timing stays unknown. Issuer fetches correlate by time, not by protected API request
ID; AWS internal traces are needed to establish worker/cache scope and causality.

Logs can arrive late. Recollect for the same window without sending more traffic:

```bash
uv run python -m repro collect results/<run>
```

Even complete API logs do not guarantee complete issuer logs. Prefetch during
Terraform deployment is outside the run window; inspect the issuer log group
separately for that. Another run can be warm: a seed or a two-hour wait does not
prove global cache readiness or a cache flush. This fixture might not reproduce an
external-provider issue. Preserve fast runs as evidence too.

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

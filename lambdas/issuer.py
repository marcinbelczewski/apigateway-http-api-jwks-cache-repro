"""Public metadata fixture: no private key, token endpoint, or application throttling."""

import json
import os
import time


def handler(event, context):
    started_ms = int(time.time() * 1000)
    path = event["rawPath"]
    issuer = f"https://{event['requestContext']['domainName']}"
    if event["requestContext"]["http"]["method"] != "GET":
        status, body = 405, {}
    elif path == "/.well-known/openid-configuration":
        status, body = (
            200,
            {
                "issuer": issuer,
                "jwks_uri": f"{issuer}/keys",
                "response_types_supported": ["id_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            },
        )
    elif path == "/keys":
        status, body = 200, json.loads(os.environ["JWKS_JSON"])
    else:
        status, body = 404, {}
    print(
        json.dumps(
            {
                "started_ms": started_ms,
                "completed_ms": int(time.time() * 1000),
                "path": path,
                "status": status,
                "lambda_request_id": context.aws_request_id,
            }
        )
    )
    return {
        "statusCode": status,
        "body": json.dumps(body),
        "headers": {
            "content-type": "application/json",
            "cache-control": "public, max-age=7200",
        },
    }

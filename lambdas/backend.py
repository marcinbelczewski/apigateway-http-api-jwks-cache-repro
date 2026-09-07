"""No-op backend. Diagnostics distinguish frontend latency from backend reuse."""

import json
import uuid

BOOT_ID = str(uuid.uuid4())
REQUEST_COUNT = 0


def handler(event, context):
    global REQUEST_COUNT
    REQUEST_COUNT += 1
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps(
            {
                "ok": True,
                "boot_id": BOOT_ID,
                "request_count": REQUEST_COUNT,
                "lambda_request_id": context.aws_request_id,
            }
        ),
    }

"""Three checks for the assumptions the experiment depends on."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jwt

import repro
from lambdas import issuer


class ReproChecks(unittest.TestCase):
    def test_token_matches_public_jwks(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.multiple(
                repro, KEY=Path(directory) / "key.pem", JWKS=Path(directory) / "jwks.json"
            ):
                repro.prepare()
                config = {
                    "issuer": "https://issuer.example",
                    "audience": "repro",
                    "jwks_sha256": hashlib.sha256(repro.JWKS.read_bytes()).hexdigest(),
                }
                token = repro.mint(config)
                jwk = json.loads(repro.JWKS.read_text())["keys"][0]
                claims = jwt.decode(
                    token,
                    jwt.PyJWK.from_dict(jwk).key,
                    algorithms=["RS256"],
                    audience=config["audience"],
                    issuer=config["issuer"],
                )
                self.assertEqual(claims["sub"], "repro")
                self.assertNotIn("d", jwk)

    def test_discovery_points_to_public_keys(self):
        event = {
            "rawPath": "/.well-known/openid-configuration",
            "requestContext": {
                "domainName": "issuer.example",
                "http": {"method": "GET"},
            },
        }
        context = SimpleNamespace(aws_request_id="test")
        metadata = json.loads(issuer.handler(event, context)["body"])
        self.assertEqual(metadata["jwks_uri"], "https://issuer.example/keys")
        with patch.dict("os.environ", {"JWKS_JSON": '{"keys":[]}'}):
            response = issuer.handler({**event, "rawPath": "/keys"}, context)
        self.assertEqual(
            (response["statusCode"], json.loads(response["body"])), (200, {"keys": []})
        )

    def test_frontend_excludes_integration_and_preserves_unknown(self):
        for response, integration, expected in [(861, 16, 845), (450, 400, 50), (900, "-", None)]:
            with self.subTest(response=response, integration=integration):
                event = {
                    "status": "200",
                    "responseLatency": response,
                    "integrationLatency": integration,
                }
                self.assertEqual(repro.frontend(event), expected)

"""Compact characterization tables for the saved-evidence calculations."""

import json
import unittest

import analyze
import repro


API = {
    "requestId": "probe",
    "status": "200",
    "requestTimeEpoch": "1000",
    "log_timestamp_ms": 9000,
    "responseLatency": "100",
    "integrationLatency": "10",
}
CLIENT = {"index": 1, "status": 200, "request_id": "probe"}


def raw(event):
    return {
        "timestamp": event["log_timestamp_ms"],
        "message": json.dumps({k: v for k, v in event.items() if k != "log_timestamp_ms"}),
    }


class EvidenceChecks(unittest.TestCase):
    def test_log_formats(self):
        for name, entries, expected in [
            ("normalized", [API], [API]),
            ("CloudWatch", [raw(API)], [API]),
            ("runtime line", [{"timestamp": 1, "message": "START RequestId: test"}], []),
            ("non-object JSON", [{"timestamp": 1, "message": "[]"}], []),
            ("empty", [], []),
        ]:
            with self.subTest(name=name):
                self.assertEqual(repro.normalize_events(entries), expected)

    def test_api_time_source(self):
        legacy = {k: v for k, v in API.items() if k != "requestTimeEpoch"}
        for name, event, expected in [
            ("explicit", API, (1000, 1100, "requestTimeEpoch")),
            ("legacy", legacy, (9000, 9100, "log_timestamp_ms")),
            ("invalid explicit", {**API, "requestTimeEpoch": "-"}, None),
            ("missing latency", {**API, "responseLatency": "-"}, None),
            ("negative latency", {**API, "responseLatency": "-1"}, None),
            ("missing log", None, None),
        ]:
            with self.subTest(name=name):
                interval = analyze.api_interval(event)
                actual = tuple(interval[k] for k in ("start_ms", "end_ms", "source")) if interval else None
                self.assertEqual(actual, expected)

    def test_log_coverage(self):
        # Outcomes: no response, returned IDs, matched IDs, responses missing ID, complete.
        for name, attempts, logged, expected in [
            ("covered", [(200, "probe")], True, (0, 1, 1, 0, True)),
            ("transport error", [(200, "probe"), (None, None)], True, (1, 1, 1, 0, True)),
            ("response missing ID", [(200, "probe"), (200, None)], True, (0, 1, 1, 1, False)),
            ("missing access log", [(200, "probe")], False, (0, 1, 0, 0, False)),
            ("HTTP failure with log", [(401, "probe")], True, (0, 1, 1, 0, True)),
            ("only transport error", [(None, None)], False, (1, 0, 0, 0, False)),
            ("empty", [], False, (0, 0, 0, 0, False)),
        ]:
            with self.subTest(name=name):
                clients = [{"status": status, "request_id": request_id} for status, request_id in attempts]
                rows = repro.join_access(clients, [API] if logged else [])
                coverage = repro.coverage(rows)
                actual = tuple(coverage[k] for k in (
                    "attempts_without_http_response", "request_ids", "matched_request_ids",
                    "responses_without_request_id", "complete",
                ))
                self.assertEqual(actual, expected)

    def test_fetch_start_boundaries(self):
        for start, with_fetch, without_fetch in [
            (999, 0, 1), (1000, 1, 0), (1099, 1, 0), (1100, 0, 1),
        ]:
            with self.subTest(start=start):
                # Completion is deliberately outside the API interval in every case.
                issuer = [{"path": "/keys", "started_ms": start, "completed_ms": 1200}]
                populations = analyze.summarize([CLIENT], [API], issuer)["successful_followups"]
                self.assertEqual(populations, {
                    "with_associated_jwks": {"count": with_fetch, "frontend_ms_range": [90, 90] if with_fetch else None},
                    "without_associated_jwks": {"count": without_fetch, "frontend_ms_range": [90, 90] if without_fetch else None},
                    "unknown": {"count": 0, "frontend_ms_range": None},
                })

    def test_analysis_formats_and_missing_timing(self):
        clients = [
            {**CLIENT, "index": 0, "request_id": "seed"},
            CLIENT,
            {**CLIENT, "index": 2, "request_id": "fast"},
            {**CLIENT, "index": 3, "request_id": "missing"},
            {"index": 4, "status": None, "error": "ConnectError"},
            {"index": 5, "status": 401, "request_id": "denied"},
        ]
        access = [
            API,
            {**API, "requestId": "seed"},
            {**API, "requestId": "fast", "requestTimeEpoch": "2000", "responseLatency": "14"},
            {**API, "requestId": "denied", "status": "401"},
        ]
        issuer = [{"path": "/keys", "started_ms": 1000, "completed_ms": 1200, "log_timestamp_ms": 1200}]
        expected = {
            "with_associated_jwks": {"count": 1, "frontend_ms_range": [90, 90]},
            "without_associated_jwks": {"count": 1, "frontend_ms_range": [4, 4]},
            "unknown": {"count": 1, "frontend_ms_range": None},
        }
        for name, encode in [("normalized", lambda e: e), ("CloudWatch", raw)]:
            with self.subTest(format=name):
                report = analyze.summarize(clients, [encode(e) for e in access], [encode(e) for e in issuer])
                self.assertEqual(report["successful_followups"], expected)
                self.assertFalse(report["coverage"]["complete"])

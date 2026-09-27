from unittest.mock import patch

from llm.client import LLMClient
from llm.redaction import REDACTED_PLACEHOLDER, redact_text


# --- redact_text: unit tests (pure, independent of LLMClient) --------------

def test_authorization_header_line_redacted():
    got = redact_text("Authorization: Bearer sometoken123")
    assert "sometoken123" not in got
    assert REDACTED_PLACEHOLDER in got


def test_bearer_token_in_prose_redacted():
    got = redact_text("use token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 to authenticate")
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in got
    assert REDACTED_PLACEHOLDER in got


def test_basic_auth_redacted():
    got = redact_text("Authorization: Basic dXNlcjpwYXNz")
    assert "dXNlcjpwYXNz" not in got


def test_cookie_and_set_cookie_header_lines_redacted():
    got = redact_text("Cookie: session=abc123; path=/\nSet-Cookie: session=abc123; HttpOnly")
    assert "abc123" not in got
    assert got.count(REDACTED_PLACEHOLDER) == 2


def test_x_api_key_header_line_redacted():
    got = redact_text("X-Api-Key: sk-live-abcdef123456")
    assert "sk-live-abcdef123456" not in got


def test_proxy_authorization_header_line_redacted():
    got = redact_text("Proxy-Authorization: Basic cHJveHk6c2VjcmV0")
    assert "cHJveHk6c2VjcmV0" not in got


def test_api_key_like_value_redacted():
    got = redact_text("api_key=sk_live_abcdef123456")
    assert "sk_live_abcdef123456" not in got
    assert "api_key=" + REDACTED_PLACEHOLDER == got


def test_password_like_field_redacted():
    for text in ("password: hunter2", "password=hunter2", "pwd=hunter2"):
        got = redact_text(text)
        assert "hunter2" not in got


def test_secrets_in_url_query_string_redacted_non_sensitive_preserved():
    got = redact_text("GET /api/login?access_token=abcdef123&user=alice")
    assert "abcdef123" not in got
    # Non-sensitive query param and path must survive unredacted.
    assert "user=alice" in got
    assert "/api/login" in got


def test_non_sensitive_security_context_preserved():
    text = (
        "Category: SQL Injection\n"
        "Endpoint: /api/v1/users\n"
        "Severity: CRITICAL\n"
        "Status: 200\n"
    )
    assert redact_text(text) == text


def test_bare_mentions_of_sensitive_words_without_kv_shape_preserved():
    # Requirement: redaction must not sacrifice analytical quality by
    # stripping ordinary prose merely for mentioning a sensitive-sounding
    # word - only an actual name+value/scheme construct is redacted.
    text = (
        "The session token is refreshed automatically every hour. "
        "Review the secret rotation policy before the next audit. "
        "This endpoint does not require a password to reach."
    )
    assert redact_text(text) == text


def test_rich_analytical_report_content_preserved_around_one_secret():
    text = (
        "Finding: Error-Based SQL Injection (CRITICAL, CVSS 9.8)\n"
        "Endpoint: /api/v1/users, parameter: id\n"
        "Authorization: Bearer abc123leaked\n"
        "Remediation: use parameterized queries and least-privilege DB roles.\n"
        "Impact: full database compromise and data exfiltration.\n"
    )
    got = redact_text(text)
    assert "abc123leaked" not in got
    for preserved in (
        "Error-Based SQL Injection",
        "CRITICAL",
        "CVSS 9.8",
        "/api/v1/users",
        "parameter: id",
        "use parameterized queries and least-privilege DB roles",
        "full database compromise and data exfiltration",
    ):
        assert preserved in got


def test_deterministic_same_input_same_output():
    text = "Authorization: Bearer abc\napi_key=xyz\nSeverity: HIGH"
    assert redact_text(text) == redact_text(text)


def test_empty_and_none_input_passthrough():
    assert redact_text("") == ""
    assert redact_text(None) is None


def test_redaction_is_idempotent():
    text = "Authorization: Bearer abc123\ntoken=xyz789"
    once = redact_text(text)
    twice = redact_text(once)
    assert "abc123" not in twice
    assert "xyz789" not in twice


# --- LLMClient: enforcement boundary integration tests ----------------------

def test_generate_summary_observation_redacts_prompt_before_sending():
    client = LLMClient(endpoint_url="http://fake-ollama:11434")
    sent_payloads = []

    class FakeResp:
        status_code = 200

        def json(self):
            return {"response": "three takeaways, no secrets here"}

    def fake_post(url, json=None, timeout=None):
        sent_payloads.append(json)
        return FakeResp()

    with patch("llm.client.requests.post", side_effect=fake_post):
        result = client.generate_summary_observation(
            "Findings summary.\nAuthorization: Bearer super-secret-token\nSeverity: CRITICAL"
        )

    assert result == "three takeaways, no secrets here"
    assert len(sent_payloads) == 1
    assert "super-secret-token" not in sent_payloads[0]["prompt"]
    assert REDACTED_PLACEHOLDER in sent_payloads[0]["prompt"]
    assert "Severity: CRITICAL" in sent_payloads[0]["prompt"]


def test_generate_summary_observation_redacts_llm_output():
    client = LLMClient(endpoint_url="http://fake-ollama:11434")

    class FakeResp:
        status_code = 200

        def json(self):
            return {"response": "Rotate this: api_key=leaked_key_123 immediately."}

    with patch("llm.client.requests.post", return_value=FakeResp()):
        result = client.generate_summary_observation("harmless prompt")

    assert "leaked_key_123" not in result
    assert REDACTED_PLACEHOLDER in result


def test_generate_summary_observation_fail_closed_on_redaction_failure():
    client = LLMClient(endpoint_url="http://fake-ollama:11434")

    def boom_post(*args, **kwargs):
        raise AssertionError("no HTTP request should be sent when input redaction fails")

    with patch("llm.client.redact_text", side_effect=RuntimeError("boom")):
        with patch("llm.client.requests.post", side_effect=boom_post):
            result = client.generate_summary_observation("some prompt")

    assert result is None


def test_generate_summary_observation_fail_closed_on_output_redaction_failure():
    client = LLMClient(endpoint_url="http://fake-ollama:11434")

    class FakeResp:
        status_code = 200

        def json(self):
            return {"response": "some response"}

    call_count = {"n": 0}

    def flaky_redact(text):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return text  # input redaction succeeds
        raise RuntimeError("boom")  # output redaction fails

    with patch("llm.client.requests.post", return_value=FakeResp()):
        with patch("llm.client.redact_text", side_effect=flaky_redact):
            result = client.generate_summary_observation("some prompt")

    assert result is None


def test_is_available_does_not_call_redaction():
    client = LLMClient(endpoint_url="http://fake-ollama:11434")

    class FakeResp:
        status_code = 200

    with patch("llm.client.requests.get", return_value=FakeResp()) as mock_get:
        with patch("llm.client.redact_text") as mock_redact:
            assert client.is_available is True
            mock_redact.assert_not_called()
    assert mock_get.called


def test_no_endpoint_url_returns_none_without_redaction_call():
    client = LLMClient(endpoint_url=None)
    with patch("llm.client.redact_text") as mock_redact:
        assert client.generate_summary_observation("prompt") is None
        mock_redact.assert_not_called()

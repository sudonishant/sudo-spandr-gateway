# sudo-spandr-gateway

A small Python helper for sending an incoming email record to the Cyber Squad policy backend. The repository currently contains the request/response client used by a planned Postfix mail-flow integration; it is **not yet a standalone listening milter daemon**.

## What is implemented

`milter_daemon.py` provides `CyberSquadMilterDaemon.process_incoming_mail(...)`. For each call it:

1. Builds a JSON object containing `sender`, `recipient`, `subject`, `body`, and `headers`.
2. Sends that object with `requests.post(..., timeout=3.0)` to the configured backend URL.
3. Returns the backend's decoded JSON when the response status is `200`.
4. Returns a fallback object with `policy_action: "ACCEPT"` and `postfix_code: "Milter.CONTINUE"` when the request fails or the response is not HTTP 200.

The default backend URL is `http://localhost:8001/api/gateway-milter-check`. A different URL can be supplied when constructing `CyberSquadMilterDaemon`.

The response is otherwise passed through unchanged. The client only logs `postfix_code` and `threat_score` when both keys are present in a successful response; it does not calculate threat scores or enforce threshold rules itself.

## Architecture

```text
caller / future Postfix adapter
              |
              v
CyberSquadMilterDaemon.process_incoming_mail()
              |
              | HTTP POST (JSON, 3-second timeout)
              v
http://localhost:8001/api/gateway-milter-check
              |
              v
       backend policy response
```

This repository does not include the backend service, a Postfix socket listener, a `pymilter` callback implementation, a service unit, or deployment configuration.

## Quick start

Use a virtual environment for local development:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m py_compile milter_daemon.py
```

The current module's executable path is only a local simulation. It sends a sample message to the default backend and prints the returned decision; it does not start a daemon or listen on port `8893`:

```bash
python milter_daemon.py
```

To use the helper from another Python process, pass a backend URL explicitly and avoid putting real message content in development fixtures:

```python
from milter_daemon import CyberSquadMilterDaemon

client = CyberSquadMilterDaemon(
    "http://127.0.0.1:8001/api/gateway-milter-check"
)
result = client.process_incoming_mail(
    sender="sender@example.test",
    recipient="recipient@example.test",
    subject="Local integration test",
    body="Non-sensitive test content.",
    headers={"X-Test-Message": "true"},
)
print(result)
```

The backend must be running and must return HTTP 200 JSON for a non-fallback result. The expected response shape is not defined in this repository; the current logger assumes successful JSON includes `postfix_code` and `threat_score`.

## Postfix integration status

There is no working Postfix milter integration in the current source. The following configuration is therefore **not a verified setup instruction** and should not be deployed as-is:

```text
smtpd_milters = inet:localhost:8893
non_smtpd_milters = inet:localhost:8893
milter_default_action = accept
```

Before connecting Postfix, an adapter still needs to create a `pymilter` listener, translate milter callbacks into `process_incoming_mail` inputs, map the backend response to an explicit milter action, and define service startup, health checks, and failure behavior.

## Configuration

There are no environment variables or configuration files in this repository. The backend URL is currently a Python constructor argument with a hard-coded default in `milter_daemon.py`; change the caller or pass a URL explicitly rather than assuming an environment variable is supported.

## Testing

No automated test suite is included. The syntax check above verifies that the module compiles, but it does not verify backend connectivity or a Postfix integration. A useful next test would mock `requests.post` and cover HTTP 200, non-200, timeout, malformed JSON, and the fallback behavior before this helper is placed in a mail path.

## Security and privacy notes

- The request includes the full email body and headers. Treat the backend connection and its logs as handling potentially sensitive mail content.
- The default URL is plain HTTP on localhost. Do not send message data over an untrusted network without adding an authenticated, encrypted transport and documenting its configuration.
- On any request exception or non-200 response, the current code returns `ACCEPT`/`Milter.CONTINUE`. That fail-open behavior may deliver mail when policy evaluation is unavailable; choose and test a failure policy before production use.
- The executable example contains a deliberately fake test message. Replace it only with non-sensitive fixtures during development.
- The client does not authenticate the backend response, validate its schema, limit payload size, or redact content. These are integration and hardening tasks, not current guarantees.

## Dependencies

- Python 3 (the module uses standard-library typing and JSON support)
- `requests>=2.31.0`
- `pymilter>=1.0.5` (declared dependency; no current source code imports or uses it)

# Changelog

## 1.4.1

### Fixes

- **No more exit on transient failures without a callback.** Without `onFailure`, a transient background check failure (network outage, timeout, `rate_limited`, `system_error`, `no_credits`, ...) no longer calls `std::exit(1)`. The SDK writes one line to `std::cerr`, `AuthForge: background check failed (<code>); retrying next interval`, keeps the session and checks in again on the next interval. Previously a brief outage killed any app that enabled online check-ins without setting a callback.
- Unchanged: without a callback, definitive failures (including the `session_expired` a transient failure becomes once the session TTL has passed) and failed `Login` calls still call `std::exit(1)`.

### Docs

- The README and `AGENTS.md` examples no longer call `std::exit(1)` from `onFailure`. They set a `std::atomic<bool>` that the main loop checks, so it can save work and return from `main`; `std::exit` is kept as a last resort after saving.

## 1.4.0

### Behavior changes for callers

- **New `authforge::AuthForgeError`** (`code()`, `isTransient()`, `isFatal()`) is thrown by the online APIs and passed as `exc` to `onFailure` (`login_failed`, `heartbeat_failed`, `selfban_failed`). For server codes `what()` equals the code. `authforge::IsTransientErrorCode(code)` exposes the same classification.
- **Classification.** Only `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app` and the SDK-local `signature_mismatch` are definitive. Everything else is transient, including `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, every `http_error_<status>`, network errors, timeouts and unknown codes. Grace period expiry, and a transient failure after the session TTL has passed, report `session_expired`.
- **Transient heartbeat failures keep checking in.** Previously the background loop stopped after any failure. Now the session is kept, `onFailure` runs, and the next check happens at the next interval.
- **Definitive heartbeat failures clear the session** (as `Logout()` does) before `onFailure` runs, so `IsAuthenticated()` is `false` inside and after the callback, and check-ins stop. Previously the session stayed authenticated.
- **Clean codes for non-2xx JSON responses on both login and heartbeat.** `what()` is `invalid_key` instead of `http_error_401: {...}`; this also changes `ValidateLicenseResult::errorCode`. Only non-JSON error pages become `http_error_<status>`.
- **New `unexpected_response` code (transient).** A failed check-in counts as a verdict only when the body is a JSON object with `"status": "failed"` and a non-empty string `error`.
- **Rate-limit retry.** Only `rate_limited`, or HTTP 429 without an error code, is retried (after 2s, then 5s). HTTP 429 `no_credits`, `app_burn_cap_reached` and `demo_quota_exceeded` are no longer retried. Network failures (after one retry) are `network_error` or `timeout`, with `what()` still `url_error: ...`.
- **Unknown server codes are passed through** (lowercase snake_case) instead of becoming `unknown_error`.
- **The heartbeat thread is no longer detached.** `Logout()` and the destructor interrupt the interval wait; the destructor joins the thread. `onFailure` runs with no SDK lock held, so calling `Logout()` / `IsAuthenticated()` from it, or destroying the client inside it, is supported. A check-in in flight across `Logout()` / `Login()` no longer writes its result back.
- **ABI change.** New private members change the `AuthForgeClient` class layout. Rebuild everything that includes `authforge_sdk.h`.
